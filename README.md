# System monitor for Claude Code

A pane beside the chat that shows how this machine is doing:

- **CPU**: how busy all cores were over the last second, with the load average and a history line of the last 60 readings (about 3 minutes while the pane is open, 30 minutes while it is closed).
- **RAM**: memory in use out of the total (counted as Activity Monitor does: app memory, wired and compressed), swap in use, and a history line.
- **Top by CPU** and **Top by memory**: the busiest processes, each with its name, pid, %CPU and resident memory, and a **Kill** button.
- **Network**: bytes per second going out (↑) and coming in (↓), a history line of both, and the programs sending the most, each with a **Kill** button.
- **Network alerts**: a program that keeps uploading, much more than it downloads, gets a card at the top of the pane with everything that can be found out about it, and **Kill** and **Ignore** buttons. See [Upload alerts](#upload-alerts).
- **Disks**: each volume you store things on, with used, free, how full it is and a bar. A volume running low turns yellow; one almost full turns red.
- **Clean up disk…**: starts a new Claude Code session that finds what takes space and plans what you could free. It deletes nothing.

A **System** button above the prompt, in every session, opens the pane, and a line under the buttons reads `CPU 34% · RAM 71% · Disk 82% · ↑ 120 KB/s ↓ 2.1 MB/s`. A number past its threshold turns yellow or red, so you notice without opening the pane. While a program trips the upload alert, the network part reads `⚠ Upload: rclone 3.2 MB/s` instead.

Nothing is sent to a model: the numbers come from `ps`, `iostat`, `vm_stat`, `sysctl`, `nettop`, `netstat`, `ioreg` and `df` (or `/proc` on Linux), so watching costs no tokens.

## Requirements

| Need | For |
|---|---|
| Claude Code with plugin mods support (tested on 2.1.300) | the pane, the line above the prompt and the `/sysmon` command |
| macOS, or Linux | the readings. On macOS every command it runs ships with the system; on Linux it reads `/proc` and `ps`, with network totals only (see [Limits](#limits)) |
| The Claude desktop app | **Clean up disk…** only, which opens a new session through the app's `claude://` link. Everything else works in a terminal too |

Nothing else to install.

## Install

```bash
claude plugin marketplace add https://git.verzth.work/ai/claude-sysmon.git
```

```bash
claude plugin install sysmon@claude-sysmon
```

From a local checkout, add the folder instead:

```bash
claude plugin marketplace add /path/to/claude-sysmon
```

Then run `/reload-plugins` (or start a new session) and open the pane with the **System** button above the prompt, or `/sysmon`. (The command is not `/tasks` or `/system`: the desktop app has its own panels by similar names.)

The pane remembers whether you left it open: close it and new sessions start without it; leave it open and it opens again in the next session.

## Using it

| Control | What it does |
| --- | --- |
| **System** (above the prompt) | Opens the pane. |
| `/sysmon` | Opens the pane. `/sysmon refresh` takes a new reading now. |
| **Kill** | Asks first: a card names the process and its pid, with **Kill <name>** and **Cancel**. Confirming sends SIGTERM, which asks the process to quit and save. If it is still running two seconds later, the card offers **Force kill (SIGKILL)**, which ends it at once. |
| **Kill** (network alert) | The same confirm, SIGTERM, then SIGKILL steps, shown inside the alert card. |
| **Ignore** (network alert) | Stops alerting on that program, by its executable path (or its name when the path is unknown), in every session and from now on. **N ignored · Show** under Network lists them with **Unignore**. |
| **Clean up disk…** | Opens a new session in the Claude desktop app with a cleanup prompt filled in, in your home folder. Press Enter there to start it. |
| **Refresh** | Takes a new reading now. |

### Kill, safely

- Some processes never get a Kill button and show 🔒 instead: pid 0 and 1, `kernel_task`, `launchd`, `WindowServer`, `loginwindow` (and `systemd`, `init` and `kthreadd` on Linux), the Claude app and every `claude` process, and the process this session runs in with every process above it.
- Before each signal the pid is looked up again. If it now belongs to a different program, or is protected, nothing is sent.
- A process of another user (or root) answers *Operation not permitted*; the pane shows that in a toast and sends nothing more.

### Upload alerts

Data theft rarely looks busy: the screen is idle, but something keeps sending. The detector watches every program's outgoing bytes (`nettop`, leaving out loopback: a server on `localhost` does not count, but an upload to another machine on your own network, such as a NAS, does) and raises an alert when a program:

- sends more than **256 KB/s for a minute** without a break, or
- sends **100 MB within 10 minutes**,

and in both cases sends at least **twice what it receives**. A video call or a download sends about as much as it gets, or less, and is left alone. An alert stays two minutes after the upload stops, so a short pause does not hide it.

Each alert card shows what could be found out about the program:

| Line | Where it comes from |
| --- | --- |
| Sent, received, rates, how long it has been steady | The `nettop` counters of the last 10 minutes |
| Program | The executable's path (`lsof -d txt`) |
| Signed | `codesign`: part of macOS, a Developer ID (with the company), the Mac App Store, a development build (an Apple Development certificate, with its owner), ad-hoc, or not signed |
| Command | Its full command line (`ps -o args`) |
| Started | When, as which user, and by which parent process |
| Sending to | The remote addresses of its open connections (`lsof -i`), established ones first |

The card turns **red** instead of yellow, with the reason spelled out, when you have been away (no keyboard or mouse for 2 minutes), when the program is unsigned, ad-hoc signed or a development build (no developer verified by Apple stands behind it), or when it runs from `/tmp`, a temporary folder, Downloads or `/Users/Shared`.

A new alert shows a toast in every open session, and one macOS notification per process in 30 minutes across all sessions, so you see it even when you come back from being away. (A program that restarts is a new process and notifies again.) (The first notification may make macOS ask whether Script Editor may show notifications.)

Backups, cloud sync (Dropbox, iCloud, Google Drive), uploads you started and VPN apps that carry other programs' traffic (Tailscale, for one) will trip it too: **Ignore** them once.

### The cleanup session

**Clean up disk…** opens `claude://code/new?q=<prompt>&folder=<home>`, the desktop app's link for a new session with a prompt. The prompt carries the current disk readings and asks the new session to:

1. measure the usual space takers with read-only commands: caches (`~/Library/Caches`, `~/.cache`, npm, pnpm, yarn, pip, Go, Gradle, CocoaPods, Homebrew), build outputs (`node_modules`, `.next`, `dist`, `build`, `target`, DerivedData, `.gradle`, Flutter builds), Docker, OrbStack or Colima images, volumes and build cache, Xcode archives, old simulators and device support files, old release artifacts (`.aab`, `.apk`, `.ipa`, `.xcarchive`, `.dmg`, `.zip`), Downloads, the Trash and old logs;
2. show a plan as a table, largest first, with each item's size, whether it is safe to remove and how it comes back;
3. give the delete commands in separate code blocks for you to run yourself, preferring a tool's own cleanup command (`docker system prune`, `brew cleanup`, `xcrun simctl delete unavailable`, `pnpm store prune`) over `rm -rf`.

It is told never to run a command that deletes, moves, prunes or empties anything. The link fills in the prompt; the session starts only when you press Enter, so you can read or change the prompt first. The link needs the Claude desktop app; in a terminal-only setup the pane says it could not open it.

## How often it reads

- While the pane is open: a new reading two seconds after the last one ended (each reading spends one second measuring CPU), so about every three seconds.
- While it is closed: every 30 seconds, enough to keep the line above the prompt current.

One reading is one short shell running `iostat`, `vm_stat`, `sysctl`, `ps`, `df`, `nettop`, `netstat` and `ioreg`; together they use a few tens of milliseconds of CPU. The details of a program (`lsof`, `codesign`) are read only while it trips the alert, at most every 20 seconds.

Because each session with the plugin reads on its own, the upload alert works while the pane is closed: every 30 seconds, so a steady upload is caught within about 90 seconds.

### Thresholds

| Reading | Yellow | Red |
| --- | --- | --- |
| CPU | 75% or more | 90% or more |
| RAM | 85% or more | 95% or more |
| Disk | under 10% or under 15 GB free | under 5% or under 5 GB free |
| Upload | a program over 256 KB/s for a minute, or 100 MB in 10 min, at least twice what it receives | the same, while you are away, or from an unsigned, ad-hoc or development-build program, or from a temporary or download folder |

### Limits

- macOS first; Linux is read from `/proc` and `ps`. Other systems show a message instead of numbers.
- %CPU per process is what `ps` reports: on macOS a short running average, on Linux the average since the process started. 100% is one full core, so a busy process can show more than 100%.
- Per-process network numbers need macOS (`nettop`). On Linux only the machine's total is watched, and an alert names no program: check with `nethogs` or `ss -tp` as root. That alert has no Kill, and **Ignore** on it silences upload alerts for the whole machine.
- On Linux an alert card shows no program details (path, signer, connections) and never turns red for being away: the idle time is read on macOS only.
- `nettop` counts what a program sent since it started; the pane measures the change between readings, so traffic before the plugin loaded is not counted.
- `lsof` and `codesign` cannot see into another user's or root's processes: their path, connections and signer may show as unknown.
- A program that sends a little at a time (under 256 KB/s and under 100 MB per 10 minutes) passes unnoticed.
- On macOS the startup disk is shown once for its whole APFS container: system, VM, preboot and recovery volumes share its free space and are left out, as are simulator runtimes and other system mounts.

## Privacy

Everything stays on this machine. The plugin writes only, in its own storage: whether the pane was open, the list of ignored programs (their names and paths), and when each upload notification was shown. Process names and disk readings go nowhere except into the cleanup prompt, and only when you press **Clean up disk…**. Command lines and connection addresses of an alerted program are shown in the pane and kept in the session's memory only.

## Development

```bash
claude plugin test .
```

```bash
claude plugin validate .
```

`hooks/model.ts` holds the commands and the parsing, and `hooks/net.ts` the network counters and the upload detector, as plain functions; `hooks/register.tsx` the hooks, the pane and the band. `hooks/band.ts` is the band layout shared with the other mods that draw above the prompt (tasklist, bi-dash, workers): keep the copies in step.

## License

MIT
