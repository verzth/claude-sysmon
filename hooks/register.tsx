import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { History, KillState, Level, Proc, Sample } from '../types'
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
  parseSample,
  pct,
  protection,
  pushHistory,
  ramLevel,
  sparkSvg,
  sparkText,
} from './model'

const PANE = 'sysmon'
const FAST_MS = 2_000 // pane open: a new sample this long after the last one ended (iostat adds one second)
const SLOW_MS = 30_000 // pane closed: enough for the band's line
const SAMPLE_TIMEOUT_MS = 15_000
const TERM_WAIT_MS = 2_000 // how long a process gets to quit after SIGTERM
const KILL_WAIT_MS = 1_000

const sampleState = atom({ plugin: 'sysmon', key: 'sample' } as const, null, { shape: 'sample-1' })
const sampleError = atom({ plugin: 'sysmon', key: 'error' } as const, null)
const history = atom({ plugin: 'sysmon', key: 'history' } as const, { cpu: [], ram: [] } as History)
const killState = atom({ plugin: 'sysmon', key: 'kill' } as const, null)
const cleanupNote = atom({ plugin: 'sysmon', key: 'cleanup' } as const, null)

let isOpen = false
let platform = ''
let home = ''
let timer: { cancel: () => void } | undefined
let sampling: Promise<void> | undefined
let stopped = false

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
  const s = parseSample(run.stdout, os, await $.clock.now())
  await update($, sampleState, () => s)
  await update($, history, prev => pushHistory(prev ?? { cpu: [], ram: [] }, s))
  await update($, sampleError, () => null)
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
  if (outcome === 'gone') $.ui.toast(`Ended ${k.name} (pid ${k.pid}) with SIG${signal}.`)
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
    await $.command.register({ name: 'sysmon', description: 'Open the System pane: CPU, RAM, disk and top processes (args: refresh)', immediate: true })
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
    const parts = s ? bandParts(s) : []
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
              onPress={() => void update($, killState, () => ({ pid: p.pid, name: p.name, stage: 'confirm' }))}
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

    const age = Math.max(0, Math.round(((await $.clock.now()) - s.at) / 1000))
    const memDetail = `${bytes(s.mem.used)} of ${bytes(s.mem.total)}${s.mem.swapTotal ? ` · swap ${bytes(s.mem.swapUsed)}` : ''}`

    return (
      <Box flexDirection="column" rowGap={1}>
        {err ? <Text color="error">{`Last reading failed: ${err}`}</Text> : null}
        {meter('cpu', 'CPU', pct(s.cpu.percent), `${s.cpu.cores} cores · load ${s.cpu.load1.toFixed(2)}`, cpuLevel(s.cpu.percent), hist.cpu)}
        {meter('ram', 'RAM', pct(s.mem.percent), memDetail, ramLevel(s.mem.percent), hist.ram)}

        {section('Top by CPU')}
        {killCard}
        <Box flexDirection="column">
          {header}
          {s.topCpu.map(p => procRow('cpu', p))}
        </Box>

        {section('Top by memory')}
        <Box flexDirection="column">
          {header}
          {s.topMem.map(p => procRow('mem', p))}
        </Box>

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
