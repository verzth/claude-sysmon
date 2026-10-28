# System monitor for Claude Code

A pane beside the chat that shows how this machine is doing:

- **CPU**: how busy all cores were over the last second, with the load average and a history line of the last readings.
- **RAM**: memory in use out of the total (counted as Activity Monitor does: app memory, wired and compressed), swap in use, and a history line.
- **Top by CPU** and **Top by memory**: the busiest processes, each with its name, pid, %CPU and resident memory, and a **Kill** button.
- **Disks**: each volume you store things on, with used, free, how full it is and a bar. A volume running low turns yellow; one almost full turns red.
- **Clean up disk…**: starts a new Claude Code session that finds what takes space and plans what you could free. It deletes nothing.

A **System** button above the prompt, in every session, opens the pane, and a line under the buttons reads `CPU 34% · RAM 71% · Disk 82%`. A number past its threshold turns yellow or red, so you notice without opening the pane.

Nothing is sent to a model: the numbers come from `ps`, `iostat`, `vm_stat`, `sysctl` and `df` (or `/proc` on Linux), so watching costs no tokens.

## Install

```bash
claude plugin marketplace add https://git.verzth.work/ai/claude-sysmon.git
```

```bash
claude plugin install sysmon@claude-sysmon
```

From a local checkout, add the folder instead:

```bash
claude plugin marketplace add ~/Workspace/ai/claude-sysmon
```

Then run `/reload-plugins` (or start a new session) and open the pane with the **System** button above the prompt, or `/sysmon`. (The command is not `/tasks` or `/system`: the desktop app has its own panels by similar names.)

## Using it

| Control | What it does |
| --- | --- |
| **System** (above the prompt) | Opens the pane. |
| `/sysmon` | Opens the pane. `/sysmon refresh` takes a new reading now. |
| **Kill** | Asks first: a card names the process and its pid, with **Kill <name>** and **Cancel**. Confirming sends SIGTERM, which asks the process to quit and save. If it is still running two seconds later, the card offers **Force kill (SIGKILL)**, which ends it at once. |
| **Clean up disk…** | Opens a new session in the Claude desktop app with a cleanup prompt filled in, in your home folder. Press Enter there to start it. |
| **Refresh** | Takes a new reading now. |

### Kill, safely

- Some processes never get a Kill button and show 🔒 instead: pid 0 and 1, `kernel_task`, `launchd`, `WindowServer`, `loginwindow` (and `systemd`/`init` on Linux), the Claude app and every `claude` process, and the process this session runs in with every process above it.
- Before each signal the pid is looked up again. If it now belongs to a different program, or is protected, nothing is sent.
- A process of another user (or root) answers *Operation not permitted*; the pane shows that in a toast and sends nothing more.

### The cleanup session

**Clean up disk…** opens `claude://code/new?q=<prompt>&folder=<home>`, the desktop app's link for a new session with a prompt. The prompt carries the current disk readings and asks the new session to:

1. measure the usual space takers with read-only commands: caches (`~/Library/Caches`, `~/.cache`, npm, pnpm, yarn, pip, Go, Gradle, CocoaPods, Homebrew), build outputs (`node_modules`, `.next`, `dist`, `build`, `target`, DerivedData, Flutter builds), Docker images and volumes, Xcode archives and old simulators, old release artifacts (`.aab`, `.apk`, `.ipa`, `.dmg`, `.zip`), Downloads, the Trash and old logs;
2. show a plan as a table, largest first, with each item's size, whether it is safe to remove and how it comes back;
3. give the delete commands in separate code blocks for you to run yourself.

It is told never to run a command that deletes, moves, prunes or empties anything. The link fills in the prompt; the session starts only when you press Enter, so you can read or change the prompt first. The link needs the Claude desktop app; in a terminal-only setup the pane says it could not open it.

## How often it reads

- While the pane is open: a new reading two seconds after the last one ended (each reading spends one second measuring CPU), so about every three seconds.
- While it is closed: every 30 seconds, enough to keep the line above the prompt current.

One reading is one short shell running `iostat`, `vm_stat`, `sysctl`, `ps` and `df`; together they use a few milliseconds of CPU.

### Thresholds

| Reading | Yellow | Red |
| --- | --- | --- |
| CPU | 75% or more | 90% or more |
| RAM | 85% or more | 95% or more |
| Disk | under 10% or under 15 GB free | under 5% or under 5 GB free |

### Limits

- macOS first; Linux is read from `/proc` and `ps`. Other systems show a message instead of numbers.
- %CPU per process is what `ps` reports: on macOS a short running average, on Linux the average since the process started. 100% is one full core, so a busy process can show more than 100%.
- On macOS the startup disk is shown once for its whole APFS container: system, VM, preboot and recovery volumes share its free space and are left out, as are simulator runtimes and other system mounts.

## Privacy

Everything stays on this machine. The plugin writes only whether the pane was open, in its own storage, so it opens again in your next session. Process names and disk readings go nowhere except into the cleanup prompt, and only when you press **Clean up disk…**.

## Development

```bash
claude plugin test .
```

```bash
claude plugin validate .
```

`hooks/model.ts` holds the commands and the parsing, as plain functions; `hooks/register.tsx` the hooks, the pane and the band. `hooks/band.ts` is the band layout shared with the other mods that draw above the prompt (tasklist, bi-dash, workers): keep the copies in step.

## License

MIT
