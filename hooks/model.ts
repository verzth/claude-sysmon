// Reading the machine: the commands one sample runs, and parsing what they print.
// Pure functions only, so the tests can feed them fixed text.

import type { Cpu, Disk, History, Level, Memory, Proc, Protection, Sample } from '../types'

export const HISTORY_LEN = 60
export const TOP_N = 8

// ---------- the commands ----------

// One shell per sample: each part prints after an @@ marker. iostat waits one second
// for a fresh CPU reading; the rest take a few milliseconds.
export const DARWIN_SCRIPT = [
  'export LC_ALL=C',
  "echo '@@self'; echo $$ $PPID",
  "echo '@@cpu'; iostat -n 0 -c 2 -w 1 | tail -1",
  "echo '@@vm'; vm_stat",
  "echo '@@sysctl'; sysctl -n hw.memsize hw.ncpu vm.swapusage",
  "echo '@@ps'; ps -Aceo pid=,ppid=,pcpu=,rss=,comm=",
  "echo '@@df'; df -kP",
].join('\n')

export const LINUX_SCRIPT = [
  'export LC_ALL=C',
  "echo '@@self'; echo $$ $PPID",
  "echo '@@stat1'; head -1 /proc/stat; sleep 1; echo '@@stat2'; head -1 /proc/stat",
  "echo '@@meminfo'; cat /proc/meminfo",
  "echo '@@ncpu'; nproc; cat /proc/loadavg",
  "echo '@@ps'; ps -Aeo pid=,ppid=,pcpu=,rss=,comm=",
  "echo '@@df'; df -kP",
].join('\n')

export function sections(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  let name = ''
  for (const line of text.split('\n')) {
    const m = /^@@(\w+)\s*$/.exec(line)
    if (m) {
      name = m[1] as string
      out[name] = ''
    } else if (name) out[name] += `${line}\n`
  }
  return out
}

const num = (s: string | undefined) => {
  const n = Number(s)
  return Number.isFinite(n) ? n : 0
}
const clampPct = (n: number) => Math.max(0, Math.min(100, Math.round(n * 10) / 10))

// ---------- CPU ----------

/** The last line of `iostat -n 0 -c 2 -w 1`: `us sy id 1m 5m 15m`. */
export function parseIostat(text: string, cores: number): Cpu {
  const t = text.trim().split(/\s+/)
  const user = num(t[0])
  const sys = num(t[1])
  const idle = t.length >= 3 ? num(t[2]) : 100
  return { percent: clampPct(100 - idle), user, sys, load1: num(t[3]), cores }
}

/** Two `cpu ...` lines of /proc/stat a second apart. */
export function parseProcStat(first: string, second: string, cores: number, load1: number): Cpu {
  const fields = (l: string) => l.trim().split(/\s+/).slice(1).map(num)
  const a = fields(first)
  const b = fields(second)
  const d = b.map((v, i) => v - (a[i] ?? 0))
  const total = d.reduce((s, v) => s + v, 0) || 1
  const idle = (d[3] ?? 0) + (d[4] ?? 0)
  const user = (((d[0] ?? 0) + (d[1] ?? 0)) / total) * 100
  const sys = (((d[2] ?? 0) + (d[5] ?? 0) + (d[6] ?? 0)) / total) * 100
  return { percent: clampPct(100 - (idle / total) * 100), user: Math.round(user), sys: Math.round(sys), load1, cores }
}

// ---------- memory ----------

const GiB = 1024 ** 3

/** `vm_stat` and `sysctl -n vm.swapusage`: used = app memory + wired + compressed, as Activity Monitor counts it. */
export function parseVmStat(vm: string, total: number, swapLine: string): Memory {
  const page = num(/page size of (\d+) bytes/.exec(vm)?.[1]) || 4096
  const pages = (label: string) => num(new RegExp(`^${label}:\\s+(\\d+)`, 'm').exec(vm)?.[1])
  const anonymous = pages('Anonymous pages')
  const app = anonymous ? anonymous - pages('Pages purgeable') : pages('Pages active')
  const usedPages = app + pages('Pages wired down') + pages('Pages occupied by compressor')
  const used = Math.min(total, usedPages * page)
  const mb = (k: string) => num(new RegExp(`${k} = ([\\d.]+)M`).exec(swapLine)?.[1]) * 1024 * 1024
  return { total, used, percent: clampPct(total ? (used / total) * 100 : 0), swapUsed: mb('used'), swapTotal: mb('total') }
}

/** /proc/meminfo: used = MemTotal - MemAvailable. */
export function parseMeminfo(text: string): Memory {
  const kb = (k: string) => num(new RegExp(`^${k}:\\s+(\\d+)`, 'm').exec(text)?.[1]) * 1024
  const total = kb('MemTotal')
  const used = Math.max(0, total - kb('MemAvailable'))
  return { total, used, percent: clampPct(total ? (used / total) * 100 : 0), swapUsed: Math.max(0, kb('SwapTotal') - kb('SwapFree')), swapTotal: kb('SwapTotal') }
}

// ---------- processes ----------

/** `ps -Ao pid=,ppid=,pcpu=,rss=,comm=`: the name is last and may hold spaces. */
export function parseProcs(text: string): Proc[] {
  const out: Proc[] = []
  for (const line of text.split('\n')) {
    const t = line.trim().split(/\s+/)
    if (t.length < 5) continue
    const pid = Number(t[0])
    if (!Number.isInteger(pid)) continue
    let name = t.slice(4).join(' ')
    // Linux ps shows a path for some; keep the last part.
    if (name.includes('/') && !name.startsWith('(')) name = name.split('/').pop() || name
    out.push({ pid, ppid: num(t[1]), cpu: num(t[2]), rss: num(t[3]) * 1024, name })
  }
  return out
}

const SYSTEM_NAMES = new Set(['kernel_task', 'launchd', 'WindowServer', 'loginwindow', 'systemd', 'init', 'kthreadd'])
const APP_NAME = /^claude(\b|$)/i

/** Why a process must not be killed from the pane, or undefined. */
export function protection(p: Pick<Proc, 'pid' | 'name'>, sessionPids: ReadonlySet<number>): Protection | undefined {
  if (p.pid <= 1 || SYSTEM_NAMES.has(p.name)) return 'system'
  if (sessionPids.has(p.pid)) return 'session'
  if (APP_NAME.test(p.name)) return 'app'
  return undefined
}

/** `pid` and every process above it: the session's own chain up to launchd. */
export function ancestors(procs: Proc[], pid: number): Set<number> {
  const parent = new Map(procs.map(p => [p.pid, p.ppid]))
  const out = new Set<number>()
  let at: number | undefined = pid
  while (at && at > 1 && !out.has(at)) {
    out.add(at)
    at = parent.get(at)
  }
  return out
}

export function topProcs(procs: Proc[], sessionPids: ReadonlySet<number>, samplerPid = 0, n = TOP_N) {
  const mark = (p: Proc): Proc => {
    const why = protection(p, sessionPids)
    return why ? { ...p, protected: why } : p
  }
  // The sampling shell and its commands are not worth a row.
  const shown = samplerPid ? procs.filter(p => p.pid !== samplerPid && p.ppid !== samplerPid) : procs
  return {
    topCpu: [...shown].sort((a, b) => b.cpu - a.cpu || b.rss - a.rss).slice(0, n).map(mark),
    topMem: [...shown].sort((a, b) => b.rss - a.rss || b.cpu - a.cpu).slice(0, n).map(mark),
  }
}

// ---------- disks ----------

const SKIP_MOUNT = /^\/(dev|proc|sys|run|snap|boot|System\/Volumes\/|private\/var\/|Library\/Developer\/|var\/lib\/docker)/

export function diskLevel(free: number, total: number): Level {
  const freePct = total ? (free / total) * 100 : 100
  if (freePct < 5 || free < 5 * GiB) return 'error'
  if (freePct < 10 || free < 15 * GiB) return 'warning'
  return 'ok'
}

/** `df -kP`, cut to the volumes a person stores things on. */
export function parseDf(text: string, platform: string): Disk[] {
  const out: Disk[] = []
  const seen = new Set<string>()
  for (const line of text.split('\n').slice(1)) {
    const m = /^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+%\s+(.+)$/.exec(line.trim())
    if (!m) continue
    const [, fs = '', sizeK, , availK, mount = ''] = m
    if (!fs.startsWith('/dev/') || fs.startsWith('/dev/loop')) continue
    if (mount !== '/' && SKIP_MOUNT.test(mount)) continue
    const total = num(sizeK) * 1024
    const free = num(availK) * 1024
    if (!total) continue
    // APFS volumes of one container share their free space: show the container once.
    const container = platform === 'darwin' ? (/^\/dev\/(disk\d+)/.exec(fs)?.[1] ?? fs) : fs
    const id = `${container}:${free}`
    if (seen.has(id)) continue
    seen.add(id)
    const used = Math.max(0, total - free)
    out.push({
      mount,
      label: mount === '/' ? (platform === 'darwin' ? 'Startup disk' : 'Root') : mount.replace(/^\/Volumes\//, ''),
      total,
      used,
      free,
      percent: clampPct((used / total) * 100),
      level: diskLevel(free, total),
    })
  }
  return out.sort((a, b) => (a.mount === '/' ? -1 : b.mount === '/' ? 1 : a.mount.localeCompare(b.mount)))
}

// ---------- one sample ----------

export function parseSample(text: string, platform: string, at: number): Sample {
  const s = sections(text)
  // The sampling shell's own pid, and its parent: the process this session runs in.
  const [samplerPid = 0, sessionPid = 0] = (s.self ?? '').trim().split(/\s+/).map(num)
  let cpu: Cpu
  let mem: Memory
  if (platform === 'darwin') {
    const [memsize, ncpu, swap = ''] = (s.sysctl ?? '').trim().split('\n')
    const cores = num(ncpu) || 1
    cpu = parseIostat(s.cpu ?? '', cores)
    mem = parseVmStat(s.vm ?? '', num(memsize), swap)
  } else {
    const [ncpu, loadavg = ''] = (s.ncpu ?? '').trim().split('\n')
    cpu = parseProcStat(s.stat1 ?? '', s.stat2 ?? '', num(ncpu) || 1, num(loadavg.split(' ')[0]))
    mem = parseMeminfo(s.meminfo ?? '')
  }
  const procs = parseProcs(s.ps ?? '')
  const chain = sessionPid ? ancestors(procs, sessionPid) : new Set<number>()
  return { at, platform, cpu, mem, ...topProcs(procs, chain, samplerPid), disks: parseDf(s.df ?? '', platform), sessionPids: [...chain] }
}

export function pushHistory(h: History, sample: Sample): History {
  return {
    cpu: [...h.cpu, sample.cpu.percent].slice(-HISTORY_LEN),
    ram: [...h.ram, sample.mem.percent].slice(-HISTORY_LEN),
  }
}

// ---------- levels and words ----------

export function cpuLevel(pct: number): Level {
  return pct >= 90 ? 'error' : pct >= 75 ? 'warning' : 'ok'
}
export function ramLevel(pct: number): Level {
  return pct >= 95 ? 'error' : pct >= 85 ? 'warning' : 'ok'
}
export const COLOR: Record<Level, string | undefined> = { ok: undefined, warning: 'warning', error: 'error' }
export const BAR_COLOR: Record<Level, string> = { ok: '#3fb950', warning: '#d29922', error: '#f85149' }

export function worst(...levels: Level[]): Level {
  return levels.includes('error') ? 'error' : levels.includes('warning') ? 'warning' : 'ok'
}

/** The main volume: the startup disk, else the first. */
export const mainDisk = (s: Sample) => s.disks.find(d => d.mount === '/') ?? s.disks[0]

export function bytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

export const pct = (n: number) => `${Math.round(n)}%`

/** `CPU 34% · RAM 71% · Disk 82%` for the band. */
export function bandParts(s: Sample): { text: string; level: Level }[] {
  const d = mainDisk(s)
  return [
    { text: `CPU ${pct(s.cpu.percent)}`, level: cpuLevel(s.cpu.percent) },
    { text: `RAM ${pct(s.mem.percent)}`, level: ramLevel(s.mem.percent) },
    ...(d ? [{ text: `Disk ${pct(d.percent)}`, level: d.level }] : []),
  ]
}

const SPARK = '▁▂▃▄▅▆▇█'
export function sparkText(values: number[], width: number): string {
  return values
    .slice(-width)
    .map(v => SPARK[Math.min(SPARK.length - 1, Math.max(0, Math.floor((v / 100) * SPARK.length)))])
    .join('')
}

export function barText(percent: number, width: number): string {
  const full = Math.round((Math.max(0, Math.min(100, percent)) / 100) * width)
  return `${'━'.repeat(full)}${'┄'.repeat(Math.max(0, width - full))}`
}

export function sparkSvg(values: number[], width: number, height: number, color: string): string {
  const pts = values.slice(-HISTORY_LEN)
  const step = pts.length > 1 ? width / (HISTORY_LEN - 1) : 0
  const x0 = width - step * (pts.length - 1)
  const line = pts.map((v, i) => `${(x0 + i * step).toFixed(1)},${(height - (Math.max(0, Math.min(100, v)) / 100) * (height - 2) - 1).toFixed(1)}`).join(' ')
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}"><rect width="${width}" height="${height}" rx="3" fill="#8881"/>${pts.length > 1 ? `<polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/>` : ''}</svg>`
}

export function barSvg(percent: number, width: number, color: string): string {
  const w = Math.round((Math.max(0, Math.min(100, percent)) / 100) * width)
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="6"><rect width="${width}" height="6" rx="3" fill="#8884"/><rect width="${w}" height="6" rx="3" fill="${color}"/></svg>`
}

// ---------- the cleanup session ----------

export function cleanupPrompt(s: Sample | null, home: string): string {
  const disks = s?.disks.length
    ? s.disks.map(d => `- ${d.label} (${d.mount}): ${bytes(d.used)} used of ${bytes(d.total)}, ${bytes(d.free)} free (${pct(d.percent)} full)`).join('\n')
    : '- (no reading yet; run `df -h` to see)'
  return `My disk is filling up. Help me find what takes space on this ${s?.platform === 'linux' ? 'Linux machine' : 'Mac'} and plan what I could free. Do NOT delete, move or empty anything yourself: only read and measure.

Disk usage right now:
${disks}

What to do:
1. Measure the usual suspects with read-only commands (du -sh, docker system df, brew --cache, ls -la), for example:
   - caches: ${home}/Library/Caches, ${home}/.cache, package-manager caches (npm, pnpm, yarn, pip, go, gradle, CocoaPods, Homebrew)
   - build outputs: node_modules, .next, dist, build, target, DerivedData, .gradle, Flutter build folders in my projects
   - Docker / OrbStack / Colima images, volumes and build cache
   - Xcode: DerivedData, Archives, old iOS / watchOS simulators and device support files
   - old release artifacts (.aab, .apk, .ipa, .xcarchive, .dmg, .zip) and large files in Downloads
   - the Trash, old logs, and other large folders in my home directory
2. Show me a plan as a table: what it is, its path, its size, whether it is safe to remove (and why), and how it comes back if needed. Largest first, with the total I could free.
3. For each item, give me the exact command to remove it, each in its own bash code block, so I run the ones I choose myself. Prefer the tool's own cleanup command (docker system prune, brew cleanup, xcrun simctl delete unavailable, pnpm store prune) over rm -rf.

Never run a command that deletes, moves, prunes or empties anything, even if it looks safe. I will run them.`
}

export function cleanupUrl(prompt: string, folder: string): string {
  const q = new URLSearchParams()
  q.set('q', prompt.slice(0, 14_000))
  if (folder) q.set('folder', folder)
  q.set('source', 'sysmon')
  return `claude://code/new?${q.toString().replace(/\+/g, '%20')}`
}
