// Network IN/OUT per process, and the upload-anomaly detector.
// Pure functions over plain data, so the tests can feed them fixed counters.

import type { Level, NetAlert, NetDetails, NetSignature } from '../types'

// ---------- thresholds ----------

const KB = 1024
const MB = 1024 * 1024
/** Sending at least this fast, and at least RATIO times faster than receiving, counts as uploading. */
export const OUT_RATE = 256 * KB
/** ...for this long without a break. */
export const SUSTAIN_MS = 60_000
/** Or this much sent in the last WINDOW_MS, out-dominant. */
export const VOLUME = 100 * MB
export const WINDOW_MS = 10 * 60_000
export const RATIO = 2
/** The person counts as away after this long without keyboard or mouse. */
export const IDLE_SEC = 120
/** An alert stays this long after the upload stopped. */
export const CLEAR_MS = 2 * 60_000

// ---------- reading the counters ----------

export type Counter = { name: string; in: number; out: number }

/** `nettop -P -L 1 -x -n -t external -J bytes_in,bytes_out`: `name.pid,in,out,` per process, bytes since it started. */
export function parseNettop(text: string): Map<number, Counter> {
  const out = new Map<number, Counter>()
  for (const line of text.split('\n')) {
    const m = /^(.*)\.(\d+),(\d+),(\d+),?\s*$/.exec(line.trim())
    if (!m) continue
    out.set(Number(m[2]), { name: m[1] as string, in: Number(m[3]), out: Number(m[4]) })
  }
  return out
}

// Tunnels and virtual links carry traffic a physical interface counts again.
const VIRTUAL_IF = /^(lo|utun|gif|stf|awdl|llw|bridge|anpi|ap\d|ipsec|vmenet|feth|docker|veth|br-|virbr|tailscale|tun|tap|wg)/

/** `netstat -ibn` (macOS): bytes in and out of the physical interfaces since boot. */
export function parseNetstat(text: string): { in: number; out: number } {
  let i = 0
  let o = 0
  for (const line of text.split('\n')) {
    const t = line.trim().split(/\s+/)
    if (!t[2]?.startsWith('<Link#') || VIRTUAL_IF.test(t[0] ?? '')) continue
    // Columns from the end: Ibytes Opkts Oerrs Obytes Coll (the Address column may be empty).
    i += Number(t[t.length - 5]) || 0
    o += Number(t[t.length - 2]) || 0
  }
  return { in: i, out: o }
}

/** /proc/net/dev (Linux): received bytes are the 1st field, sent the 9th. */
export function parseProcNetDev(text: string): { in: number; out: number } {
  let i = 0
  let o = 0
  for (const line of text.split('\n')) {
    const m = /^\s*([^:\s]+):\s*(.*)$/.exec(line)
    if (!m || VIRTUAL_IF.test(m[1] as string)) continue
    const f = (m[2] as string).trim().split(/\s+/).map(Number)
    i += f[0] || 0
    o += f[8] || 0
  }
  return { in: i, out: o }
}

// ---------- tracking over time ----------

type Point = { at: number; in: number; out: number }
type Track = { name: string; points: Point[]; highSince?: number; alertSince?: number; lastAlert?: number }
export type Tracker = { procs: Map<number, Track>; total: Point[] }

export const newTracker = (): Tracker => ({ procs: new Map(), total: [] })

export type ProcStat = {
  pid: number
  name: string
  inRate: number
  outRate: number
  sent: number
  received: number
  /** How long it has been uploading without a break, ms. */
  sustainedMs: number
  /** Set while the process trips the detector, and for CLEAR_MS after. */
  alertSince?: number
}

function push(points: Point[], p: Point) {
  const last = points[points.length - 1]
  // A counter that went down is a new process under a reused pid.
  if (last && (p.out < last.out || p.in < last.in)) points.length = 0
  points.push(p)
  // Keep the window, plus the one point just before it as its baseline.
  while (points.length > 2 && (points[1] as Point).at <= p.at - WINDOW_MS) points.shift()
}

function rates(points: Point[]) {
  const last = points[points.length - 1] as Point
  const prev = points[points.length - 2]
  const dt = prev ? (last.at - prev.at) / 1000 : 0
  // push() keeps the window plus one point before it: the first point is the baseline.
  const base = points[0] as Point
  return {
    inRate: dt > 0 && prev ? (last.in - prev.in) / dt : 0,
    outRate: dt > 0 && prev ? (last.out - prev.out) / dt : 0,
    prevAt: prev?.at,
    sent: last.out - base.out,
    received: last.in - base.in,
  }
}

/** Feeds one reading; returns each process's rates and whether it trips the detector. */
export function step(t: Tracker, at: number, counters: Map<number, Counter>, total: { in: number; out: number }): ProcStat[] {
  push(t.total, { at, ...total })
  for (const pid of [...t.procs.keys()]) if (!counters.has(pid)) t.procs.delete(pid)
  const out: ProcStat[] = []
  for (const [pid, c] of counters) {
    let tr = t.procs.get(pid)
    if (!tr || tr.name !== c.name) {
      tr = { name: c.name, points: [] }
      t.procs.set(pid, tr)
    }
    push(tr.points, { at, in: c.in, out: c.out })
    const r = rates(tr.points)
    const uploading = r.outRate >= OUT_RATE && r.outRate >= RATIO * r.inRate
    if (!uploading) tr.highSince = undefined
    else if (tr.highSince === undefined) tr.highSince = r.prevAt ?? at
    const sustainedMs = tr.highSince === undefined ? 0 : at - tr.highSince
    const trips = (uploading && sustainedMs >= SUSTAIN_MS) || (r.sent >= VOLUME && r.sent >= RATIO * r.received)
    if (trips) {
      tr.lastAlert = at
      tr.alertSince ??= at
    } else if (tr.lastAlert === undefined || at - tr.lastAlert > CLEAR_MS) tr.alertSince = undefined
    out.push({ pid, name: c.name, inRate: r.inRate, outRate: r.outRate, sent: r.sent, received: r.received, sustainedMs, alertSince: tr.alertSince })
  }
  return out
}

export function totalRates(t: Tracker): { inRate: number; outRate: number } {
  const last = t.total[t.total.length - 1]
  const prev = t.total[t.total.length - 2]
  if (!last || !prev || last.at <= prev.at) return { inRate: 0, outRate: 0 }
  const dt = (last.at - prev.at) / 1000
  return { inRate: Math.max(0, (last.in - prev.in) / dt), outRate: Math.max(0, (last.out - prev.out) / dt) }
}

// ---------- what a process is ----------

/** One shell that describes a process: its executable, owner, parent, command line, connections and signer. */
export function detailsScript(pid: number): string {
  const p = String(Math.trunc(pid))
  return [
    'export LC_ALL=C',
    `p=${p}`,
    `path=$(lsof -nP -a -p $p -d txt -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)`,
    // lsof cannot read another user's process; ps still names its executable.
    'if [ -z "$path" ]; then c=$(ps -o comm= -p $p); case "$c" in /*) path=$c;; esac; fi',
    'echo @@path; echo "$path"',
    'echo @@ps; ps -o user=,ppid=,lstart= -p $p',
    'echo @@args; ps -o args= -p $p',
    'echo @@parent; pp=$(ps -o ppid= -p $p | tr -d " "); [ -n "$pp" ] && ps -c -o pid=,comm= -p "$pp"',
    'echo @@lsof; lsof -nP -a -p $p -i 2>/dev/null | head -60',
    'echo @@sign; [ -n "$path" ] && command -v codesign >/dev/null && codesign -dv --verbose=2 "$path" 2>&1 | head -30',
    'true',
  ].join('\n')
}

export function parseSignature(text: string): NetSignature | undefined {
  const t = text.trim()
  if (!t) return undefined
  if (/not signed at all/.test(t)) return { kind: 'unsigned', text: 'Not signed' }
  const auth = /^Authority=(.+)$/m.exec(t)?.[1]
  if (/^Platform identifier=/m.test(t) || /^(macOS )?Software Signing$/.test(auth ?? '')) return { kind: 'apple', text: 'Apple (part of macOS)' }
  if (auth?.startsWith('Developer ID Application:')) return { kind: 'developer', text: `Developer ID: ${auth.replace('Developer ID Application: ', '')}` }
  if (auth && /Apple Mac OS Application Signing|App Store/.test(auth)) return { kind: 'appstore', text: 'Mac App Store' }
  if (auth?.startsWith('Apple Development:')) return { kind: 'adhoc', text: `Development build: ${auth.replace('Apple Development: ', '')}` }
  if (/Signature=adhoc/.test(t) || (/^Identifier=/m.test(t) && !auth)) return { kind: 'adhoc', text: 'Ad-hoc signed (no verified developer)' }
  if (auth) return { kind: 'developer', text: auth }
  return { kind: 'unknown', text: t.split('\n').pop()?.slice(0, 120) ?? 'Unknown' }
}

/** Remote ends of the process's sockets, established first, at most 6. */
export function parseRemotes(lsof: string): string[] {
  const est: string[] = []
  const other: string[] = []
  for (const line of lsof.split('\n')) {
    const m = /->(\S+)/.exec(line)
    if (!m) continue
    const remote = m[1] as string
    const proto = /\b(TCP|UDP)\b/.exec(line)?.[1] ?? ''
    const entry = proto === 'UDP' ? `${remote} (UDP)` : remote
    ;(/ESTABLISHED/.test(line) ? est : other).push(entry)
  }
  return [...new Set([...est, ...other])].slice(0, 6)
}

export function parseDetails(text: string, sectionsOf: (t: string) => Record<string, string>): NetDetails {
  const s = sectionsOf(text)
  const ps = (s.ps ?? '').trim().split(/\s+/)
  const parent = (s.parent ?? '').trim()
  const pm = /^(\d+)\s+(.+)$/.exec(parent)
  const args = (s.args ?? '').trim()
  return {
    path: (s.path ?? '').trim() || undefined,
    user: ps[0] || undefined,
    started: ps.length > 2 ? ps.slice(2).join(' ') : undefined,
    parent: pm ? `${pm[2]} (pid ${pm[1]})` : undefined,
    args: args ? (args.length > 300 ? `${args.slice(0, 299)}…` : args) : undefined,
    remotes: parseRemotes(s.lsof ?? ''),
    signature: parseSignature(s.sign ?? ''),
  }
}

const TEMP_PATH = /^\/(private\/)?(tmp|var\/tmp|var\/folders)\/|^\/Users\/[^/]+\/Downloads\/|^\/Users\/Shared\//

/** Why this upload looks risky, worst first; what decides the alert's colour. */
export function alertNotes(a: Pick<NetAlert, 'idleSec' | 'details'>): { level: Level; notes: string[] } {
  const notes: string[] = []
  let level: Level = 'warning'
  const d = a.details
  if (a.idleSec >= IDLE_SEC) {
    notes.push(`You have been away ${Math.round(a.idleSec / 60)} min while it kept sending.`)
    level = 'error'
  }
  if (d?.signature?.kind === 'unsigned' || d?.signature?.kind === 'adhoc') {
    notes.push(`${d.signature.text}: no verified developer stands behind it.`)
    level = 'error'
  }
  if (d?.path && TEMP_PATH.test(d.path)) {
    notes.push('It runs from a temporary or download folder.')
    level = 'error'
  }
  return { level, notes }
}

export function rateText(bytesPerSec: number): string {
  const b = Math.max(0, bytesPerSec)
  if (b < 1024) return `${Math.round(b)} B/s`
  if (b < MB) return `${Math.round(b / KB)} KB/s`
  return `${(b / MB).toFixed(b < 10 * MB ? 1 : 0)} MB/s`
}

export function duration(ms: number): string {
  const s = Math.round(ms / 1000)
  if (s < 90) return `${s} s`
  const m = Math.round(s / 60)
  return m < 90 ? `${m} min` : `${(m / 60).toFixed(1)} h`
}

/** The key Ignore remembers: the executable's path when known, else its name. */
export const ignoreKey = (a: { name: string; details?: NetDetails }) => a.details?.path ?? a.name

export function notificationScript(title: string, body: string): string {
  const q = (s: string) => `"${s.replace(/["\\]/g, ' ').slice(0, 200)}"`
  return `display notification ${q(body)} with title ${q(title)}`
}

/** Rates as 0-100 of the larger of their peak and 1 MB/s, so a quiet line stays low. */
export function scaled(values: number[], peak = Math.max(MB, ...values)): number[] {
  return values.map(v => (Math.max(0, v) / peak) * 100)
}

/** Sent (orange) and received (blue) over the last readings, on one scale. */
export function netSparkSvg(inVals: number[], outVals: number[], width: number, height: number): string {
  const peak = Math.max(MB, ...inVals, ...outVals)
  const line = (vals: number[], color: string) => {
    const pts = scaled(vals, peak)
    if (pts.length < 2) return ''
    const step = width / 59
    const x0 = width - step * (pts.length - 1)
    const p = pts.map((v, i) => `${(x0 + i * step).toFixed(1)},${(height - (v / 100) * (height - 2) - 1).toFixed(1)}`).join(' ')
    return `<polyline points="${p}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/>`
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}"><rect width="${width}" height="${height}" rx="3" fill="#8881"/>${line(inVals, '#58a6ff')}${line(outVals, '#f0883e')}</svg>`
}
