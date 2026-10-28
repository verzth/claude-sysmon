import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { History, IgnoredNet, KillState, Level, Net, NetAlert, NetDetails, NetProc, Proc, Sample } from '../types'
import { band } from './band'
import {
  BAR_COLOR,
  bandParts,
  barSvg,
  barText,
  bytes,
  cleanupPrompt,
  cleanupUrl,
  COLOR,
  cpuLevel,
  DARWIN_SCRIPT,
  LINUX_SCRIPT,
  parseProcs,
  parseSample,
  pct,
  protection,
  pushHistory,
  ramLevel,
  sparkSvg,
  sparkText,
  sections,
} from './model'
import {
  alertNotes,
  CLEAR_MS,
  type Counter,
  detailsScript,
  duration,
  ignoreKey,
  newTracker,
  notificationScript,
  OUT_RATE,
  parseDetails,
  parseNetstat,
  parseNettop,
  parseProcNetDev,
  netSparkSvg,
  rateText,
  scaled,
  step,
  totalRates,
  VOLUME,
  WINDOW_MS,
} from './net'

const PANE = 'sysmon'
const FAST_MS = 2_000 // pane open: a new sample this long after the last one ended (iostat adds one second)
const SLOW_MS = 30_000 // pane closed: enough for the band's line
const SAMPLE_TIMEOUT_MS = 15_000
const TERM_WAIT_MS = 2_000 // how long a process gets to quit after SIGTERM
const KILL_WAIT_MS = 1_000

const sampleState = atom({ plugin: 'sysmon', key: 'sample' } as const, null, { shape: 'sample-2' })
const sampleError = atom({ plugin: 'sysmon', key: 'error' } as const, null)
const history = atom({ plugin: 'sysmon', key: 'history' } as const, { cpu: [], ram: [] } as History)
const killState = atom({ plugin: 'sysmon', key: 'kill' } as const, null)
const cleanupNote = atom({ plugin: 'sysmon', key: 'cleanup' } as const, null)
const alertsState = atom({ plugin: 'sysmon', key: 'alerts' } as const, [] as NetAlert[])
const ignoredState = atom({ plugin: 'sysmon', key: 'ignoredNet' } as const, [] as IgnoredNet[])
const showIgnored = atom({ plugin: 'sysmon', key: 'showIgnored' } as const, false)

const NET_TOP = 6 // senders listed under Network
const DETAILS_TTL_MS = 20_000 // how long a process's details (connections above all) are reused
const NOTIFY_AGAIN_MS = 30 * 60_000 // one macOS notification per process in this long, across sessions
const HISTORY_LEN = 60

let isOpen = false
let platform = ''
let home = ''
let timer: { cancel: () => void } | undefined
let sampling: Promise<void> | undefined
let stopped = false
let tracker = newTracker()
const detailCache = new Map<number, { name: string; at: number; details: NetDetails }>()
const announced = new Set<string>()

const errText = (err: unknown) => (err instanceof Error ? err.message : String(err))

// ---------- sampling ----------

async function detectPlatform($: EngineInterface): Promise<string> {
  if (platform) return platform
  const run = await $.process.run(['uname', '-s'], { timeoutMs: 5_000 })
  const os = run.stdout.trim()
  platform = os === 'Darwin' ? 'darwin' : os === 'Linux' ? 'linux' : os.toLowerCase() || 'unknown'
  return platform
}

async function sampleOnce($: EngineInterface) {
  const os = await detectPlatform($)
  if (os !== 'darwin' && os !== 'linux') throw new Error(`System monitor reads macOS and Linux; this machine is ${os}.`)
  const run = await $.process.run(['sh', '-c', os === 'darwin' ? DARWIN_SCRIPT : LINUX_SCRIPT], { timeoutMs: SAMPLE_TIMEOUT_MS })
  if (!run.stdout.includes('@@ps')) throw new Error(run.stderr.trim().split('\n').pop() || `sampling exited with ${run.exitCode}`)
  const at = await $.clock.now()
  const s = parseSample(run.stdout, os, at)
  const net = await readNet($, os, run.stdout, s, at)
  if (net) s.net = net
  await update($, sampleState, () => s)
  await update($, history, prev => {
    const h = pushHistory(prev ?? { cpu: [], ram: [] }, s)
    if (!net) return h
    return { ...h, netIn: [...(prev?.netIn ?? []), net.inRate].slice(-HISTORY_LEN), netOut: [...(prev?.netOut ?? []), net.outRate].slice(-HISTORY_LEN) }
  })
  await update($, sampleError, () => null)
}

// ---------- network ----------

const isIgnored = (a: { name: string; details?: NetDetails }, list: IgnoredNet[]) =>
  list.some(i => i.key === a.name || (a.details?.path !== undefined && i.key === a.details.path))

async function details($: EngineInterface, pid: number, name: string, at: number): Promise<NetDetails | undefined> {
  if (platform !== 'darwin' || pid <= 0) return undefined
  const hit = detailCache.get(pid)
  if (hit && hit.name === name && at - hit.at < DETAILS_TTL_MS) return hit.details
  try {
    const run = await $.process.run(['sh', '-c', detailsScript(pid)], { timeoutMs: 10_000 })
    const d = parseDetails(run.stdout, sections)
    detailCache.set(pid, { name, at, details: d })
    return d
  } catch {
    return hit?.details
  }
}

/** The ignore list, as every session shares it through the plugin's store. */
async function loadIgnored($: EngineInterface): Promise<IgnoredNet[]> {
  const stored = (await $.store.get('netIgnore')) as IgnoredNet[] | undefined
  const list = Array.isArray(stored) ? stored : []
  const now = await read($, ignoredState)
  if (JSON.stringify(now) !== JSON.stringify(list)) await update($, ignoredState, () => list)
  return list
}

async function readNet($: EngineInterface, os: string, text: string, s: Sample, at: number): Promise<Net | undefined> {
  const sec = sections(text)
  let counters: Map<number, Counter>
  let total: { in: number; out: number }
  const perProcess = os === 'darwin' && !!sec.nettop?.trim()
  if (os === 'darwin') {
    counters = parseNettop(sec.nettop ?? '')
    total = parseNetstat(sec.netstat ?? '')
  } else {
    total = parseProcNetDev(sec.netdev ?? '')
    // No per-process counters without root: the machine's total stands in, and can trip the detector too.
    counters = new Map([[0, { name: 'All traffic', ...total }]])
  }
  if (sec.netstat === undefined && sec.netdev === undefined) return undefined
  const stats = step(tracker, at, counters, total)
  const names = new Map(parseProcs(sec.ps ?? '').map(p => [p.pid, p.name]))
  const chain = new Set(s.sessionPids)
  const nameOf = (pid: number, fallback: string) => names.get(pid) ?? fallback
  const guard = (pid: number, name: string) => (pid > 0 ? protection({ pid, name }, chain) : 'system')
  const idleSec = Number((sec.idle ?? '').trim()) || 0
  const tot = totalRates(tracker)

  const top: NetProc[] = (perProcess ? stats : [])
    .filter(x => x.outRate > 0 || x.inRate > 0)
    .sort((a, b) => b.outRate - a.outRate || b.inRate - a.inRate)
    .slice(0, NET_TOP)
    .map(x => {
      const name = nameOf(x.pid, x.name)
      const why = guard(x.pid, name)
      return { pid: x.pid, name, inRate: x.inRate, outRate: x.outRate, sent: x.sent, received: x.received, ...(why ? { protected: why } : {}) }
    })

  const ignored = await loadIgnored($)
  const alerts: NetAlert[] = []
  for (const x of stats) {
    if (x.alertSince === undefined) continue
    const name = nameOf(x.pid, x.name)
    const d = await details($, x.pid, name, at)
    const why = guard(x.pid, name)
    const a: NetAlert = {
      pid: x.pid,
      name,
      since: x.alertSince,
      inRate: x.inRate,
      outRate: x.outRate,
      sent: x.sent,
      received: x.received,
      sustainedMs: x.sustainedMs,
      idleSec,
      ...(d ? { details: d } : {}),
      ...(why ? { protected: why } : {}),
    }
    if (!isIgnored(a, ignored)) alerts.push(a)
  }
  alerts.sort((a, b) => b.outRate - a.outRate)
  await update($, alertsState, () => alerts)
  for (const a of alerts) await announce($, a, at)
  for (const pid of [...detailCache.keys()]) if (!counters.has(pid)) detailCache.delete(pid)
  return { perProcess, inRate: tot.inRate, outRate: tot.outRate, top, idleSec }
}

/** A toast in this session, and one macOS notification per process across sessions: the person may be away. */
async function announce($: EngineInterface, a: NetAlert, at: number) {
  const key = `${a.pid}:${a.name}`
  if (announced.has(key)) return
  announced.add(key)
  $.ui.toast(`Unusual upload: ${a.name} (pid ${a.pid}) sent ${bytes(a.sent)} recently, now ${rateText(a.outRate)}. Open System to review it.`)
  if (platform !== 'darwin') return
  try {
    const seen = ((await $.store.get('netNotified')) ?? {}) as Record<string, number>
    if (seen[key] !== undefined && at - seen[key] < NOTIFY_AGAIN_MS) return
    const kept = Object.fromEntries(Object.entries(seen).filter(([, t]) => at - t < 24 * 3_600_000))
    await $.store.set('netNotified', { ...kept, [key]: at })
    await $.process.run(['osascript', '-e', notificationScript('Unusual upload', `${a.name} (pid ${a.pid}) is sending ${rateText(a.outRate)}: ${bytes(a.sent)} in the last 10 min.`)], { timeoutMs: 10_000 })
  } catch {}
}

async function ignoreAlert($: EngineInterface, a: NetAlert) {
  const key = ignoreKey(a)
  const now = await $.clock.now()
  const list = await update($, ignoredState, l => (l.some(i => i.key === key) ? l : [...l, { key, name: a.name, at: now }]))
  await $.store.set('netIgnore', list)
  await update($, alertsState, l => l.filter(x => !isIgnored(x, list)))
  $.ui.toast(`Ignoring uploads from ${a.name}. Unignore it under Network.`)
}

async function unignore($: EngineInterface, key: string) {
  const list = await update($, ignoredState, l => l.filter(i => i.key !== key))
  await $.store.set('netIgnore', list)
}

/** One sample at a time; a second ask waits for the one under way. */
function sampleNow($: EngineInterface): Promise<void> {
  if (!sampling)
    sampling = sampleOnce($)
      .catch(err => update($, sampleError, () => errText(err)).then(() => undefined))
      .finally(() => {
        sampling = undefined
      })
  return sampling
}

/** Sample, then come back fast while the pane is open and slowly otherwise. */
function loop($: EngineInterface) {
  timer?.cancel()
  timer = undefined
  if (stopped) return
  void sampleNow($).then(() => {
    if (stopped) return
    timer?.cancel()
    timer = $.clock.after(isOpen ? FAST_MS : SLOW_MS, () => loop($))
  })
}

async function openPane($: EngineInterface) {
  const placed = await $.ui.open({ id: PANE, title: 'System', columns: 72, rows: 44 })
  const wasOpen = isOpen
  isOpen = placed.isPlaced
  await $.store.set('open', true)
  if (isOpen && !wasOpen) loop($) // from the slow pace to the fast one, now
}

async function autoOpen($: EngineInterface) {
  if ((await $.store.get('open')) !== true) return
  await openPane($).catch(err => $.ui.log(`sysmon: ${errText(err)}`))
}

// ---------- kill ----------

/** The process's name now, or undefined when it is gone. */
async function nameOf($: EngineInterface, pid: number): Promise<string | undefined> {
  const argv = platform === 'darwin' ? ['ps', '-c', '-p', String(pid), '-o', 'comm='] : ['ps', '-p', String(pid), '-o', 'comm=']
  const run = await $.process.run(argv, { timeoutMs: 5_000 })
  const name = run.stdout.trim()
  return run.exitCode === 0 && name ? name.split('/').pop() : undefined
}

async function isAlive($: EngineInterface, pid: number): Promise<boolean> {
  const run = await $.process.run(['kill', '-0', String(pid)], { timeoutMs: 5_000 })
  // EPERM means it exists but belongs to someone else.
  return run.exitCode === 0 || /not permitted/i.test(run.stderr)
}

/** Sends `signal` after checking the pid still names the same, unprotected process. */
async function send($: EngineInterface, k: KillState, signal: 'TERM' | 'KILL'): Promise<'gone' | 'alive' | 'stopped'> {
  const s = await read($, sampleState)
  if (protection(k, new Set(s?.sessionPids ?? []))) {
    $.ui.toast(`${k.name} (pid ${k.pid}) is protected; nothing was sent.`)
    return 'stopped'
  }
  const now = await nameOf($, k.pid)
  if (now === undefined) {
    $.ui.toast(`${k.name} (pid ${k.pid}) had already quit.`)
    return 'gone'
  }
  if (now !== k.name) {
    $.ui.toast(`pid ${k.pid} is now "${now}", not ${k.name}; nothing was sent.`)
    return 'stopped'
  }
  const run = await $.process.run(['kill', `-${signal}`, String(k.pid)], { timeoutMs: 5_000 })
  if (run.exitCode !== 0) {
    $.ui.toast(`Could not send SIG${signal} to ${k.name}: ${run.stderr.trim().replace(/^.*kill: /, '') || `exit code ${run.exitCode}`}`)
    return 'stopped'
  }
  await $.clock.sleep(signal === 'TERM' ? TERM_WAIT_MS : KILL_WAIT_MS)
  return (await isAlive($, k.pid)) ? 'alive' : 'gone'
}

async function runKill($: EngineInterface, signal: 'TERM' | 'KILL') {
  const k = await read($, killState)
  if (!k) return
  await update($, killState, () => ({ ...k, stage: signal === 'TERM' ? 'sending' : 'forcing' }))
  let outcome: 'gone' | 'alive' | 'stopped'
  try {
    outcome = await send($, k, signal)
  } catch (err) {
    $.ui.toast(`Could not end ${k.name}: ${errText(err)}`)
    outcome = 'stopped'
  }
  if (outcome === 'alive') {
    if (signal === 'TERM') await update($, killState, () => ({ ...k, stage: 'alive' }))
    else {
      $.ui.toast(`${k.name} (pid ${k.pid}) is still running after SIGKILL.`)
      await update($, killState, () => null)
    }
    return
  }
  if (outcome === 'gone') {
    $.ui.toast(`Ended ${k.name} (pid ${k.pid}) with SIG${signal}.`)
    await update($, alertsState, l => l.filter(a => a.pid !== k.pid))
  }
  await update($, killState, () => null)
  void sampleNow($)
}

// ---------- cleanup ----------

async function startCleanup($: EngineInterface) {
  if (!home) home = (await $.env.get('HOME')) ?? ''
  const url = cleanupUrl(cleanupPrompt(await read($, sampleState), home), home)
  const argv = platform === 'linux' ? ['xdg-open', url] : ['open', url]
  try {
    const run = await $.process.run(argv, { timeoutMs: 10_000 })
    if (run.exitCode !== 0) throw new Error(run.stderr.trim() || `exit code ${run.exitCode}`)
    await update($, cleanupNote, () => 'A new session opened with the cleanup prompt filled in: press Enter there to start it. It only measures and plans; you run the delete commands yourself.')
  } catch (err) {
    await update($, cleanupNote, () => `Could not open a new session (${errText(err)}). The deep link needs the Claude desktop app.`)
  }
}

// ---------- register ----------

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    const started = await next(e)
    stopped = false
    home = (await $.env.get('HOME')) ?? ''
    tracker = newTracker()
    await loadIgnored($).catch(() => undefined)
    await $.command.register({ name: 'sysmon', description: 'Open the System pane: CPU, RAM, network, disk and top processes (args: refresh)', immediate: true })
    loop($)
    if (e.isInteractive && e.surface) await autoOpen($)
    return started
  })

  on('session.attach', { surface: 'desktop' }, async ($, e, next) => {
    const attached = await next(e)
    $.clock.after(50, () => void autoOpen($))
    return attached
  })

  on('session.end', async ($, e, next) => {
    stopped = true
    timer?.cancel()
    return next(e)
  })

  on('command.run', { command: 'sysmon' }, async ($, e) => {
    if (e.args.trim() === 'refresh') {
      await sampleNow($)
      const err = await read($, sampleError)
      return { text: err ? `Could not read the system: ${err}` : 'System numbers refreshed.' }
    }
    await openPane($)
    return { text: 'System pane opened.' }
  })

  on('ui.close', ($, e, next) => {
    if (e.id === PANE) {
      isOpen = false
      if (e.origin.kind === 'person') void $.store.set('open', false).catch(() => undefined)
    }
    return next(e)
  })

  // ---------- the band above the prompt ----------

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const previous = await next(e)
    if (e.props.hasSurvey) return previous
    const { Box, Button, Text } = $.ui.resolve(e)
    const s = await read($, sampleState)
    const alerts = await read($, alertsState)
    const parts = s ? bandParts(s) : []
    if (alerts.length) {
      const a = alerts[0] as NetAlert
      const level = alerts.some(x => alertNotes(x).level === 'error') ? 'error' : 'warning'
      parts.push({ text: `⚠ Upload: ${a.name} ${rateText(a.outRate)}${alerts.length > 1 ? ` · ${alerts.length - 1} more` : ''}`, level })
    } else if (s?.net) parts.push({ text: `↑ ${rateText(s.net.outRate)} ↓ ${rateText(s.net.inRate)}`, level: 'ok' })
    const line = parts.length ? (
      <Text wrap="truncate-end">
        {parts.flatMap((p, i) => [
          ...(i ? [<Text dimColor>{' · '}</Text>] : []),
          p.level === 'ok' ? <Text dimColor>{p.text}</Text> : <Text color={COLOR[p.level]}>{p.text}</Text>,
        ])}
      </Text>
    ) : null
    return band(
      Box as unknown as (p: Record<string, unknown>) => unknown,
      previous,
      [<Button key="open-sysmon" label="System" onPress={() => void openPane($)} />],
      line ? [line] : [],
    ) as ReturnType<typeof Box>
  })

  // ---------- the pane ----------

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const table = $.ui.resolve(e)
    const { Box, Text, Button } = table
    const Svg = e.surface !== 'terminal' && 'Svg' in table ? table.Svg : undefined
    if (!isOpen) {
      // Drawn without openPane (a restored layout): poll fast from now, outside the drawing.
      isOpen = true
      $.clock.after(0, () => loop($))
    }

    const s = await read($, sampleState)
    const err = await read($, sampleError)
    const hist = (await read($, history)) ?? { cpu: [], ram: [] }
    const k = await read($, killState)
    const note = await read($, cleanupNote)
    const alerts = await read($, alertsState)
    const ignored = await read($, ignoredState)
    const ignoredShown = await read($, showIgnored)
    const cols = Math.max(30, e.props.bodyColumns)
    const px = Math.max(200, Math.min(900, cols * 8))

    if (!s)
      return (
        <Box flexDirection="column" rowGap={1}>
          <Text dimColor={!err} color={err ? 'error' : undefined}>
            {err ? `Could not read the system: ${err}` : 'Reading CPU, memory and disks…'}
          </Text>
        </Box>
      )

    const meter = (key: string, title: string, value: string, detail: string, level: Level, series: number[]) => (
      <Box key={key} flexDirection="column">
        <Box flexDirection="row" columnGap={1}>
          <Text weight="semibold">{title}</Text>
          <Text color={COLOR[level]} weight="semibold">
            {value}
          </Text>
          <Text dimColor wrap="truncate-end">
            {detail}
          </Text>
        </Box>
        {Svg ? (
          <Svg key={`${key}-spark`} alt={`${title} over the last ${series.length} readings`} width={px} height={28} source={sparkSvg(series, px, 28, BAR_COLOR[level])} />
        ) : (
          <Text color={COLOR[level]} dimColor={level === 'ok'}>
            {sparkText(series, Math.min(60, cols - 2))}
          </Text>
        )}
      </Box>
    )

    const PROTECTED_LABEL = { system: 'system', app: 'Claude', session: 'this session' } as const
    const procRow = (list: string, p: Proc) => (
      <Box key={`${list}-${p.pid}`} flexDirection="row" columnGap={1} alignItems="center">
        <Box flexGrow={1} flexShrink={1} minWidth={8}>
          <Text wrap="truncate-end" dimColor={!!p.protected}>
            {p.name}
          </Text>
        </Box>
        <Box width={7} justifyContent="flex-end">
          <Text dimColor>{String(p.pid)}</Text>
        </Box>
        <Box width={7} justifyContent="flex-end">
          <Text color={p.cpu >= 80 ? 'warning' : undefined}>{`${p.cpu.toFixed(1)}%`}</Text>
        </Box>
        <Box width={9} justifyContent="flex-end">
          <Text>{bytes(p.rss)}</Text>
        </Box>
        <Box width={13} justifyContent="flex-end">
          {p.protected ? (
            <Text dimColor>{`🔒 ${PROTECTED_LABEL[p.protected]}`}</Text>
          ) : (
            <Button
              key={`kill-${list}-${p.pid}`}
              label="Kill"
              dimColor
              onPress={() => void update($, killState, (): KillState => ({ pid: p.pid, name: p.name, stage: 'confirm', from: list === 'mem' ? 'mem' : 'cpu' }))}
            />
          )}
        </Box>
      </Box>
    )

    const header = (
      <Box flexDirection="row" columnGap={1}>
        <Box flexGrow={1}>
          <Text dimColor>Process</Text>
        </Box>
        <Box width={7} justifyContent="flex-end">
          <Text dimColor>pid</Text>
        </Box>
        <Box width={7} justifyContent="flex-end">
          <Text dimColor>CPU</Text>
        </Box>
        <Box width={9} justifyContent="flex-end">
          <Text dimColor>Memory</Text>
        </Box>
        <Box width={13} />
      </Box>
    )

    const killCard = k ? (
      <Box key="kill-card" flexDirection="column" rowGap={1} borderStyle="round" borderColor="warning" paddingX={1}>
        {k.stage === 'confirm' ? (
          <Box flexDirection="column" rowGap={1}>
            <Text color="warning" weight="semibold">{`Kill ${k.name} (pid ${k.pid})?`}</Text>
            <Text dimColor>It gets SIGTERM first, which asks it to quit and save. Unsaved work in it may be lost.</Text>
            <Box flexDirection="row" columnGap={1}>
              <Button key="kill-confirm" variant="primary" label={`Kill ${k.name}`} onPress={() => void runKill($, 'TERM')} />
              <Button key="kill-cancel" label="Cancel" onPress={() => void update($, killState, () => null)} />
            </Box>
          </Box>
        ) : k.stage === 'alive' ? (
          <Box flexDirection="column" rowGap={1}>
            <Text color="error" weight="semibold">{`${k.name} (pid ${k.pid}) is still running after SIGTERM.`}</Text>
            <Text dimColor>SIGKILL ends it at once, with no chance to save.</Text>
            <Box flexDirection="row" columnGap={1}>
              <Button key="kill-force" variant="primary" label="Force kill (SIGKILL)" onPress={() => void runKill($, 'KILL')} />
              <Button key="kill-cancel" label="Cancel" onPress={() => void update($, killState, () => null)} />
            </Box>
          </Box>
        ) : (
          <Text dimColor>{`Sending SIG${k.stage === 'forcing' ? 'KILL' : 'TERM'} to ${k.name} (pid ${k.pid})…`}</Text>
        )}
      </Box>
    ) : null

    const diskRows = s.disks.map(d => (
      <Box key={`disk-${d.mount}`} flexDirection="column">
        <Box flexDirection="row" columnGap={1}>
          <Text weight="semibold">{d.label}</Text>
          <Text dimColor wrap="truncate-end">
            {d.mount}
          </Text>
          <Box flexGrow={1} />
          <Text color={COLOR[d.level]} weight={d.level === 'ok' ? undefined : 'semibold'}>{`${pct(d.percent)} full`}</Text>
        </Box>
        {Svg ? (
          <Svg key={`disk-bar-${d.mount}`} alt={`${pct(d.percent)} used`} width={px} height={6} source={barSvg(d.percent, px, BAR_COLOR[d.level])} />
        ) : (
          <Text color={COLOR[d.level]} dimColor={d.level === 'ok'}>
            {barText(d.percent, Math.min(60, cols - 2))}
          </Text>
        )}
        <Text dimColor={d.level === 'ok'} color={COLOR[d.level]}>
          {`${bytes(d.used)} used · ${bytes(d.free)} free of ${bytes(d.total)}${d.level === 'error' ? ' · almost full' : d.level === 'warning' ? ' · running low' : ''}`}
        </Text>
      </Box>
    ))

    const section = (title: string) => (
      <Text key={`h-${title}`} weight="bold">
        {title}
      </Text>
    )

    const killAt = (from: 'cpu' | 'mem' | 'net', pid?: number) => (k && (k.from ?? 'cpu') === from && (pid === undefined || k.pid === pid) ? killCard : null)
    const askKill = (pid: number, name: string) => () => void update($, killState, (): KillState => ({ pid, name, stage: 'confirm', from: 'net' }))
    const label = (what: string, value: string | undefined, key: string) =>
      value ? (
        <Box key={key} flexDirection="row" columnGap={1}>
          <Box width={9} flexShrink={0}>
            <Text dimColor>{what}</Text>
          </Box>
          <Box flexGrow={1} flexShrink={1}>
            <Text wrap="wrap">{value}</Text>
          </Box>
        </Box>
      ) : null

    const alertCard = (a: NetAlert) => {
      const { level, notes } = alertNotes(a)
      const d = a.details
      const steady = a.sustainedMs >= 60_000 ? ` · steady for ${duration(a.sustainedMs)}` : ''
      const killShown = k?.from === 'net' && k.pid === a.pid
      return (
        <Box key={`alert-${a.pid}`} flexDirection="column" rowGap={1} borderStyle="round" borderColor={COLOR[level]} paddingX={1}>
          <Text color={COLOR[level]} weight="semibold">{`⚠ ${a.name}${a.pid ? ` (pid ${a.pid})` : ''} keeps uploading`}</Text>
          <Text>{`Sent ${bytes(a.sent)} and received ${bytes(a.received)} in the last ${duration(WINDOW_MS)} · now ↑ ${rateText(a.outRate)} ↓ ${rateText(a.inRate)}${steady}`}</Text>
          {notes.map((n, i) => (
            <Text key={`note-${a.pid}-${i}`} color={COLOR[level]}>
              {n}
            </Text>
          ))}
          <Box flexDirection="column">
            {label('Program', d?.path ?? (a.pid ? 'path unknown' : undefined), `path-${a.pid}`)}
            {label('Signed', d?.signature?.text, `sign-${a.pid}`)}
            {label('Command', d?.args, `args-${a.pid}`)}
            {label('Started', [d?.started, d?.user ? `as ${d.user}` : '', d?.parent ? `by ${d.parent}` : ''].filter(Boolean).join(' · ') || undefined, `start-${a.pid}`)}
            {label('Sending to', d ? (d.remotes.length ? d.remotes.join(', ') : 'no open connection found right now') : undefined, `remote-${a.pid}`)}
            {a.pid ? null : label('Note', 'Linux shows no per-process traffic; check with nethogs or ss -tp as root.', 'linux-note')}
          </Box>
          {killShown ? killCard : null}
          <Box flexDirection="row" columnGap={1} alignItems="center">
            {a.protected ? (
              <Text dimColor>{`🔒 ${PROTECTED_LABEL[a.protected]}: no Kill`}</Text>
            ) : killShown ? null : (
              <Button key={`net-kill-${a.pid}`} label={`Kill ${a.name}`} onPress={askKill(a.pid, a.name)} />
            )}
            <Button key={`net-ignore-${a.pid}`} label="Ignore" dimColor onPress={() => void ignoreAlert($, a)} />
          </Box>
        </Box>
      )
    }

    const net = s.net
    const netHeader = (
      <Box flexDirection="row" columnGap={1}>
        <Box flexGrow={1}>
          <Text dimColor>Process</Text>
        </Box>
        <Box width={7} justifyContent="flex-end">
          <Text dimColor>pid</Text>
        </Box>
        <Box width={10} justifyContent="flex-end">
          <Text dimColor>↑ up</Text>
        </Box>
        <Box width={10} justifyContent="flex-end">
          <Text dimColor>↓ down</Text>
        </Box>
        <Box width={13} />
      </Box>
    )
    const netRow = (p: NetProc) => (
      <Box key={`net-${p.pid}`} flexDirection="row" columnGap={1} alignItems="center">
        <Box flexGrow={1} flexShrink={1} minWidth={8}>
          <Text wrap="truncate-end" dimColor={!!p.protected}>
            {p.name}
          </Text>
        </Box>
        <Box width={7} justifyContent="flex-end">
          <Text dimColor>{String(p.pid)}</Text>
        </Box>
        <Box width={10} justifyContent="flex-end">
          <Text color={p.outRate >= OUT_RATE ? 'warning' : undefined}>{rateText(p.outRate)}</Text>
        </Box>
        <Box width={10} justifyContent="flex-end">
          <Text>{rateText(p.inRate)}</Text>
        </Box>
        <Box width={13} justifyContent="flex-end">
          {p.protected ? (
            <Text dimColor>{`🔒 ${PROTECTED_LABEL[p.protected]}`}</Text>
          ) : (
            <Button key={`kill-net-${p.pid}`} label="Kill" dimColor onPress={askKill(p.pid, p.name)} />
          )}
        </Box>
      </Box>
    )
    const netSection = net ? (
      <Box key="net" flexDirection="column" rowGap={1}>
        <Box flexDirection="column">
          <Box flexDirection="row" columnGap={1}>
            <Text weight="semibold">Network</Text>
            <Text color={net.outRate >= OUT_RATE ? 'warning' : undefined} weight="semibold">{`↑ ${rateText(net.outRate)}`}</Text>
            <Text weight="semibold">{`↓ ${rateText(net.inRate)}`}</Text>
            <Text dimColor wrap="truncate-end">
              {net.idleSec >= 60 ? `· you have been away ${duration(net.idleSec * 1000)}` : '· up orange, down blue'}
            </Text>
          </Box>
          {Svg ? (
            <Svg key="net-spark" alt={`Network over the last ${(hist.netOut ?? []).length} readings`} width={px} height={28} source={netSparkSvg(hist.netIn ?? [], hist.netOut ?? [], px, 28)} />
          ) : (
            <Text dimColor>{`↑ ${sparkText(scaled(hist.netOut ?? []), Math.min(60, cols - 4))}`}</Text>
          )}
        </Box>
        {k?.from === 'net' && !alerts.some(a => a.pid === k.pid) ? killCard : null}
        {net.perProcess ? (
          net.top.length ? (
            <Box flexDirection="column">
              {netHeader}
              {net.top.map(netRow)}
            </Box>
          ) : (
            <Text dimColor>No process is sending or receiving right now.</Text>
          )
        ) : (
          <Text dimColor>Per-process traffic needs macOS (nettop); here only the machine's total is watched.</Text>
        )}
        <Text dimColor wrap="wrap">{`Alerts when a program sends over ${rateText(OUT_RATE)} for a minute, or ${bytes(VOLUME)} in ${duration(WINDOW_MS)}, at least twice what it receives. An alert stays ${duration(CLEAR_MS)} after it stops.`}</Text>
        {ignored.length ? (
          <Box flexDirection="column">
            <Button key="net-show-ignored" label={`${ignored.length} ignored · ${ignoredShown ? 'Hide' : 'Show'}`} dimColor onPress={() => void update($, showIgnored, v => !v)} />
            {ignoredShown
              ? ignored.map(i => (
                  <Box key={`ignored-${i.key}`} flexDirection="row" columnGap={1} alignItems="center">
                    <Box flexGrow={1} flexShrink={1}>
                      <Text wrap="truncate-start" dimColor>
                        {i.key === i.name ? i.name : `${i.name} · ${i.key}`}
                      </Text>
                    </Box>
                    <Button key={`net-unignore-${i.key}`} label="Unignore" dimColor onPress={() => void unignore($, i.key)} />
                  </Box>
                ))
              : null}
          </Box>
        ) : null}
      </Box>
    ) : null

    const age = Math.max(0, Math.round(((await $.clock.now()) - s.at) / 1000))
    const memDetail = `${bytes(s.mem.used)} of ${bytes(s.mem.total)}${s.mem.swapTotal ? ` · swap ${bytes(s.mem.swapUsed)}` : ''}`

    return (
      <Box flexDirection="column" rowGap={1}>
        {err ? <Text color="error">{`Last reading failed: ${err}`}</Text> : null}
        {alerts.length ? section('Network alerts') : null}
        {alerts.map(alertCard)}
        {meter('cpu', 'CPU', pct(s.cpu.percent), `${s.cpu.cores} cores · load ${s.cpu.load1.toFixed(2)}`, cpuLevel(s.cpu.percent), hist.cpu)}
        {meter('ram', 'RAM', pct(s.mem.percent), memDetail, ramLevel(s.mem.percent), hist.ram)}

        {section('Top by CPU')}
        {killAt('cpu')}
        <Box flexDirection="column">
          {header}
          {s.topCpu.map(p => procRow('cpu', p))}
        </Box>

        {section('Top by memory')}
        {killAt('mem')}
        <Box flexDirection="column">
          {header}
          {s.topMem.map(p => procRow('mem', p))}
        </Box>

        {netSection}

        {section('Disks')}
        {s.disks.length ? diskRows : <Text dimColor>No volumes found.</Text>}
        <Box flexDirection="row" columnGap={1} alignItems="center">
          <Button key="cleanup" label="Clean up disk…" onPress={() => void startCleanup($)} />
          <Text dimColor wrap="wrap">
            New session that finds what takes space and plans it; deletes nothing.
          </Text>
        </Box>
        {note ? <Text dimColor>{note}</Text> : null}

        <Box flexDirection="row" columnGap={1} alignItems="center">
          <Text dimColor>{`Updated ${age}s ago · every ${FAST_MS / 1000 + 1}s while open, ${SLOW_MS / 1000}s otherwise`}</Text>
          <Button key="refresh" label="Refresh" dimColor onPress={() => void sampleNow($)} />
        </Box>
      </Box>
    )
  })
}
