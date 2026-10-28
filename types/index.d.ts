// What one sample of the machine holds, and what the pane draws from it.

export type Level = 'ok' | 'warning' | 'error'

export type Cpu = {
  /** Busy share of all cores over the last second, 0-100. */
  percent: number
  user: number
  sys: number
  /** One-minute load average. */
  load1: number
  cores: number
}

export type Memory = {
  /** Bytes. */
  total: number
  used: number
  percent: number
  swapUsed: number
  swapTotal: number
}

/** Why Kill is not offered for a process. */
export type Protection = 'system' | 'app' | 'session'

export type Proc = {
  pid: number
  ppid: number
  name: string
  /** %CPU as ps reports it: 100 is one full core. */
  cpu: number
  /** Resident memory, bytes. */
  rss: number
  protected?: Protection
}

export type Disk = {
  mount: string
  label: string
  /** Bytes. */
  total: number
  used: number
  free: number
  percent: number
  level: Level
}

/** A process's network traffic over the last readings, bytes per second. */
export type NetProc = {
  pid: number
  name: string
  inRate: number
  outRate: number
  /** Bytes sent and received in the last 10 minutes. */
  sent: number
  received: number
  protected?: Protection
}

export type Net = {
  /** False on Linux: only the machine's totals are known. */
  perProcess: boolean
  inRate: number
  outRate: number
  /** Busiest senders first. */
  top: NetProc[]
  /** Seconds since the last keyboard or mouse input; 0 when unknown. */
  idleSec: number
}

export type NetSignature = {
  kind: 'apple' | 'developer' | 'appstore' | 'adhoc' | 'unsigned' | 'unknown'
  text: string
}

/** What could be found out about a process that trips the detector. */
export type NetDetails = {
  path?: string
  user?: string
  started?: string
  parent?: string
  args?: string
  remotes: string[]
  signature?: NetSignature
}

/** A process sending a lot, steadily, more than it receives. */
export type NetAlert = {
  pid: number
  name: string
  since: number
  inRate: number
  outRate: number
  sent: number
  received: number
  sustainedMs: number
  idleSec: number
  details?: NetDetails
  protected?: Protection
}

/** A process the person told the detector to leave alone, by executable path or name. */
export type IgnoredNet = { key: string; name: string; at: number }

export type Sample = {
  at: number
  platform: string
  cpu: Cpu
  mem: Memory
  topCpu: Proc[]
  topMem: Proc[]
  disks: Disk[]
  /** This session's process and the ones above it: never offered for Kill. */
  sessionPids: number[]
  net?: Net
}

export type History = { cpu: number[]; ram: number[]; netIn?: number[]; netOut?: number[] }

/** A Kill in progress: asked, sent, or still alive after SIGTERM. */
export type KillState = {
  pid: number
  name: string
  stage: 'confirm' | 'sending' | 'alive' | 'forcing'
  /** The section whose Kill was pressed: the card shows there. */
  from?: 'cpu' | 'mem' | 'net'
}

declare module 'claude-code' {
  interface PluginState {
    sysmon: {
      sample: Shaped<Sample | null>
      error: string | null
      history: History
      kill: KillState | null
      cleanup: string | null
      alerts: NetAlert[]
      ignoredNet: IgnoredNet[]
      showIgnored: boolean
    }
  }
}
