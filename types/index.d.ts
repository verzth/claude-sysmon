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
}

export type History = { cpu: number[]; ram: number[] }

/** A Kill in progress: asked, sent, or still alive after SIGTERM. */
export type KillState = {
  pid: number
  name: string
  stage: 'confirm' | 'sending' | 'alive' | 'forcing'
}

declare module 'claude-code' {
  interface PluginState {
    sysmon: {
      sample: Shaped<Sample | null>
      error: string | null
      history: History
      kill: KillState | null
      cleanup: string | null
    }
  }
}
