import { expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'
import type { TestBody } from 'claude-code/testing'

import { cleanupPrompt, parseDf, parseProcs, parseSample, protection } from '../hooks/model'

const PANE = {
  plugin: 'sysmon',
  component: 'Pane',
  requestId: 'sysmon',
  props: {
    title: 'System',
    isFocused: false,
    bodyColumns: 70,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 80 },
    view: {},
  },
} as const

const BAND = {
  plugin: 'sysmon',
  component: 'AbovePrompt',
  props: { hasSurvey: false, isWorking: false, maxRows: 4, bodyColumns: 80, scroll: { offset: 0, bodyRows: 4 }, view: {} },
} as const

const NOW = Date.UTC(2026, 9, 28, 10, 0, 0)
const GiB = 1024 ** 3

// What the macOS sampling shell prints: the shell is pid 900, run by the session (pid 800).
const PS = [
  '    1     0   0.0  12000 launchd',
  '  300     1   0.0 900000 kernel_task',
  '  620     1  45.0  80000 WindowServer',
  '  700     1   2.0 400000 Claude',
  '  800   700   1.5 380000 claude',
  '  900   800   0.0   1000 sh',
  '  901   900   0.0   2000 ps',
  ' 4242     1  88.5 512000 Google Chrome Helper (Renderer)',
  ' 5555     1  12.0 2097152 node',
  ' 6000     1   0.0    800 sleep',
].join('\n')

const DF = [
  'Filesystem 1024-blocks Used Available Capacity Mounted on',
  '/dev/disk3s1s1 971350180 13337964 77398248 15% /',
  'devfs 230 230 0 100% /dev',
  '/dev/disk3s6 971350180 24152096 77398248 24% /System/Volumes/VM',
  '/dev/disk3s5 971350180 843936572 77398248 92% /System/Volumes/Data',
  'map auto_home 0 0 0 100% /System/Volumes/Data/home',
  '/dev/disk3s3 971350180 1506020 77398248 2% /Volumes/Recovery',
  '/dev/disk7s1 17659904 17159516 455144 98% /Library/Developer/CoreSimulator/Volumes/iOS_23F77',
  '/dev/disk20s1 976762584 476762584 500000000 49% /Volumes/Backup Drive',
].join('\n')

const VM = `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                    61464.
Pages active:                                 363918.
Pages wired down:                             437931.
Pages purgeable:                                 204.
Anonymous pages:                              438377.
Pages occupied by compressor:                1077005.
`

const sampleText = (idle = 66) =>
  [
    '@@self',
    '900 800',
    '@@cpu',
    `   25  9 ${idle}  3.10 3.00 2.90`,
    '@@vm',
    VM,
    '@@sysctl',
    '38654705664\n14\ntotal = 2048.00M  used = 512.00M  free = 1536.00M  (encrypted)',
    '@@ps',
    PS,
    '@@df',
    DF,
  ].join('\n')

function engine(on: On) {
  const clock = mock.clock(on, { now: NOW })
  mock.store(on)
  mock.env(on, { HOME: '/Users/budi' })
  const calls = {
    clock,
    runs: [] as (readonly string[])[],
    toasts: [] as string[],
    idle: 66,
    /** pid → name for `ps -p`; missing means gone. */
    alive: { 4242: 'Google Chrome Helper (Renderer)', 5555: 'node' } as Record<number, string>,
    /** pids that ignore SIGTERM. */
    stubborn: new Set<number>(),
  }
  on('process.run', (_, e) => {
    const argv = e.argv
    calls.runs.push(argv)
    const ok = (stdout = '', exitCode = 0, stderr = '') => ({ value: { exitCode, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false } })
    if (argv[0] === 'uname') return ok('Darwin\n')
    if (argv[0] === 'sh') return ok(sampleText(calls.idle))
    if (argv[0] === 'ps') {
      const pid = Number(argv[argv.indexOf('-p') + 1])
      const name = calls.alive[pid]
      return name ? ok(`${name}\n`) : ok('', 1)
    }
    if (argv[0] === 'kill') {
      const pid = Number(argv[2])
      if (!(pid in calls.alive)) return ok('', 1, `kill: ${pid}: No such process`)
      if (argv[1] === '-TERM' && !calls.stubborn.has(pid)) delete calls.alive[pid]
      if (argv[1] === '-KILL') delete calls.alive[pid]
      return ok()
    }
    if (argv[0] === 'open') return ok()
    return ok('', 127, 'not found')
  })
  on('command.register', () => ({ value: { command: 'sysmon' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.toast', (_, e) => {
    calls.toasts.push(String(e.text))
    return { value: undefined }
  })
  on('ui.log', () => ({ value: undefined }))
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  return calls
}

async function started($: Parameters<TestBody>[0], calls: ReturnType<typeof engine>) {
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await calls.clock.settle()
}

// ---------- parsing ----------

test('a macOS sample: CPU, RAM, processes and volumes', () => {
  const s = parseSample(sampleText(), 'darwin', NOW)
  expect(s.cpu.percent).toBe(34)
  expect(s.cpu.cores).toBe(14)
  expect(Math.round(s.mem.used / GiB)).toBe(30) // (anonymous - purgeable + wired + compressed) pages
  expect(s.mem.swapUsed).toBe(512 * 1024 * 1024)
  expect(s.topCpu[0]?.name).toBe('Google Chrome Helper (Renderer)')
  expect(s.topMem[0]?.name).toBe('node')
  expect(s.topCpu.some(p => p.name === 'sh' || p.name === 'ps'), 'the sampler is left out').toBe(false)
  expect(s.sessionPids.sort()).toEqual([700, 800])
})

test('the startup disk counts the whole APFS container; system and simulator volumes are left out', () => {
  const disks = parseDf(DF, 'darwin')
  expect(disks.map(d => d.mount)).toEqual(['/', '/Volumes/Backup Drive'])
  expect(disks[0]?.percent).toBe(92)
  expect(disks[0]?.level).toBe('warning')
  expect(disks[1]?.label).toBe('Backup Drive')
  expect(disks[1]?.level).toBe('ok')
})

test('protected processes', () => {
  const session = new Set([700, 800])
  expect(protection({ pid: 1, name: 'launchd' }, session)).toBe('system')
  expect(protection({ pid: 300, name: 'kernel_task' }, session)).toBe('system')
  expect(protection({ pid: 620, name: 'WindowServer' }, session)).toBe('system')
  expect(protection({ pid: 800, name: 'claude' }, session)).toBe('session')
  expect(protection({ pid: 999, name: 'Claude Helper (Renderer)' }, session)).toBe('app')
  expect(protection({ pid: 4242, name: 'Google Chrome Helper' }, session)).toBeUndefined()
})

test('Linux ps names keep their last path part', () => {
  expect(parseProcs('  10   1  1.0  2048 /usr/bin/python3')[0]?.name).toBe('python3')
})

// ---------- the pane ----------

test('the pane shows CPU, RAM, top processes and disks, on every surface', async ($, on) => {
  const calls = engine(on)
  await started($, calls)
  for (const surface of ['desktop', 'terminal'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect(await ui.find({ type: 'Text', text: '34%' }), 'CPU').toBeTruthy()
    expect(await ui.find({ type: 'Text', text: '83%' }), 'RAM').toBeTruthy()
    expect(await ui.find({ type: 'Text', text: /29\.8 GB of 36\.0 GB · swap 512 MB/ })).toBeTruthy()
    expect(await ui.find({ type: 'Button', key: 'kill-cpu-4242' })).toBeTruthy()
    expect(await ui.find({ type: 'Button', key: 'kill-cpu-620' }), 'WindowServer is protected').toBeUndefined()
    expect(await ui.find({ type: 'Button', key: 'kill-mem-800' }), 'this session is protected').toBeUndefined()
    expect(await ui.find({ type: 'Button', key: 'kill-mem-700' }), 'the Claude app is protected').toBeUndefined()
    expect(await ui.find({ type: 'Text', text: '🔒 this session' })).toBeTruthy()
    expect(await ui.find({ type: 'Text', text: '92% full' })).toBeTruthy()
    expect(await ui.find({ type: 'Text', text: /free of .* · running low/ })).toBeTruthy()
    expect(await ui.find({ type: 'Button', key: 'cleanup' })).toBeTruthy()
    await ui.unmount()
  }
})

test('Kill asks first, sends SIGTERM, and the process is gone', async ($, on) => {
  const calls = engine(on)
  await started($, calls)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })

  await ui.press({ key: 'kill-cpu-4242' })
  expect(calls.runs.some(a => a[0] === 'kill'), 'nothing sent before the confirm').toBe(false)
  expect(await ui.find({ type: 'Text', text: 'Kill Google Chrome Helper (Renderer) (pid 4242)?' })).toBeTruthy()

  await ui.press({ key: 'kill-cancel' })
  expect(await ui.find({ type: 'Button', key: 'kill-confirm' })).toBeUndefined()
  expect(calls.runs.some(a => a[0] === 'kill')).toBe(false)

  await ui.press({ key: 'kill-cpu-4242' })
  await ui.press({ key: 'kill-confirm' })
  await calls.clock.advance(2_500)
  expect(calls.runs.some(a => a.join(' ') === 'kill -TERM 4242')).toBe(true)
  expect(calls.runs.some(a => a.join(' ') === 'kill -KILL 4242'), 'no SIGKILL when SIGTERM worked').toBe(false)
  expect(calls.toasts.at(-1)).toBe('Ended Google Chrome Helper (Renderer) (pid 4242) with SIGTERM.')
  expect(await ui.find({ type: 'Button', key: 'kill-force' })).toBeUndefined()
  await ui.unmount()
})

test('a process that survives SIGTERM is offered SIGKILL', async ($, on) => {
  const calls = engine(on)
  calls.stubborn.add(5555)
  await started($, calls)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })

  await ui.press({ key: 'kill-mem-5555' })
  await ui.press({ key: 'kill-confirm' })
  await calls.clock.advance(2_500)
  expect(await ui.find({ type: 'Text', text: 'node (pid 5555) is still running after SIGTERM.' })).toBeTruthy()
  await ui.press({ key: 'kill-force' })
  await calls.clock.advance(1_500)
  expect(calls.runs.some(a => a.join(' ') === 'kill -KILL 5555')).toBe(true)
  expect(calls.toasts.at(-1)).toBe('Ended node (pid 5555) with SIGKILL.')
  await ui.unmount()
})

test('Kill sends nothing when the pid now names another process', async ($, on) => {
  const calls = engine(on)
  await started($, calls)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  await ui.press({ key: 'kill-cpu-4242' })
  calls.alive[4242] = 'Finder'
  await ui.press({ key: 'kill-confirm' })
  await calls.clock.advance(2_500)
  expect(calls.runs.some(a => a[0] === 'kill')).toBe(false)
  expect(calls.toasts.at(-1)).toBe('pid 4242 is now "Finder", not Google Chrome Helper (Renderer); nothing was sent.')
  await ui.unmount()
})

test('Cleanup opens a new desktop session with the cleanup prompt', async ($, on) => {
  const calls = engine(on)
  await started($, calls)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  await ui.press({ key: 'cleanup' })
  await calls.clock.settle()
  const open = calls.runs.find(a => a[0] === 'open')
  expect(open).toBeTruthy()
  const url = new URL(String(open?.[1]))
  expect(url.protocol).toBe('claude:')
  expect(url.host + url.pathname).toBe('code/new')
  expect(url.searchParams.get('folder')).toBe('/Users/budi')
  const prompt = url.searchParams.get('q') ?? ''
  expect(prompt).toContain('Do NOT delete')
  expect(prompt).toContain('Startup disk (/)')
  expect(prompt).toContain('bash code block')
  expect(await ui.find({ type: 'Text', text: /A new session opened with the cleanup prompt/ })).toBeTruthy()
  await ui.unmount()
})

test('the cleanup prompt never asks the new session to delete', () => {
  const p = cleanupPrompt(null, '/Users/budi')
  expect(p).toContain('Never run a command that deletes')
  expect(p).toContain('/Users/budi/Library/Caches')
})

// ---------- the band ----------

test('the band shows one line and a button that opens the pane', async ($, on) => {
  const calls = engine(on)
  calls.idle = 5 // CPU 95%: past the threshold
  on('ui.render', { component: 'AbovePrompt' }, ($, e) => {
    const { Box } = $.ui.resolve(e)
    return <Box /> // nothing else draws in the band
  })
  await started($, calls)
  const band = await $.ui.mount({ ...BAND, surface: 'desktop' })
  expect(await band.find({ type: 'Button', key: 'open-sysmon' })).toBeTruthy()
  expect((await band.find({ type: 'Text', text: /^CPU/ }))?.text).toBe('CPU 95% · RAM 83% · Disk 92%')
  // Each part is its own span, coloured past its threshold.
  const line = await band.find({ type: 'Text', text: /^CPU/ })
  const spans = (line?.children ?? []) as { props: { color?: string; dimColor?: boolean }; children: string[] }[]
  const colorOf = (t: string) => spans.find(c => c.children[0] === t)?.props
  expect(colorOf('CPU 95%')?.color).toBe('error')
  expect(colorOf('RAM 83%')?.dimColor, 'RAM is fine').toBe(true)
  expect(colorOf('Disk 92%')?.color).toBe('warning')
  await band.press({ key: 'open-sysmon' })
  await band.unmount()
})

test('polling is fast while the pane is open and slow otherwise', async ($, on) => {
  const calls = engine(on)
  const samples = () => calls.runs.filter(a => a[0] === 'sh').length
  await started($, calls)
  expect(samples()).toBe(1)
  await calls.clock.advance(10_000)
  expect(samples(), 'closed: nothing in 10 s').toBe(1)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  await calls.clock.advance(10_000)
  expect(samples()).toBeGreaterThan(3)
  await ui.unmount()
})
