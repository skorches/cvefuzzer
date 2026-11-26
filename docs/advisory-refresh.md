# Scheduling advisory refresh

CVEFuzz runs once and exits. An operating-system scheduler can periodically invoke the same updater used for manual refresh. All projects to monitor must already have a saved dependency scan in the selected database. The latest saved dependency attempt per root is authoritative, including unsuccessful attempts. The updater does not reread repositories or install dependencies.

Use a trusted Python environment with CVEFuzz installed. First run the command manually with absolute paths and inspect its JSON report:

```powershell
& 'C:\path to\cvefuzzer\.venv\Scripts\python.exe' -m cvefuzz refresh --all --min-age-hours 24 --database 'C:\path to\cvefuzzer\.cvefuzz\scans.sqlite3' --output 'C:\path to\cvefuzzer\.cvefuzz\scheduled-refresh.json' --fail-on never
```

Change the 24-hour query interval, per-request `--timeout`, and `--retries` as needed. Successful recent projects are skipped; failures are retried on the next scheduled invocation. A failed latest dependency scan still needs a new `scan`; refreshing older inventories is not a substitute. Partial project inventories continue to produce exit 2 even if their saved components were queried successfully.

Exit 0 with `--fail-on never` means the scheduled run completed under the configured interval policy, including possible skips. Exit 2 means a failure, offline/unavailable checks, an empty database, or incomplete original coverage. With the default `--fail-on findings`, exit 1 indicates retained/current findings; use `--fail-on never` for schedulers that should treat findings as report content while still detecting operational failures. Review `projects --newly-affected` separately; findings are never sent to another service or person by the scheduler recipes, apart from the normal OSV matching queries.

Every project has its own atomic successful cache and attempt history. A hard runtime limit can interrupt the current project; its previous cache survives, and earlier completed project refreshes remain committed. An interruption may leave no history entry for the interrupted attempt. Whole-batch reports can be absent or represent an earlier run if the process stops before writing them. Consult per-scan `history` and project timestamps rather than treating an old report file as a new success. Both recipes avoid overlapping instances of the same task; independent/manual updaters can still run, with optimistic cache conflict checks.

## Windows Task Scheduler

Use Windows PowerShell on a machine with the ScheduledTasks module. Update the paths below. The task runs daily at 03:00 in the machine's local timezone under the current user's interactive session, with limited privileges. This example needs the user to be logged in. Configure a different account/logon policy through Task Scheduler if unattended operation while logged out is required.

The following commands **register a real local scheduled task** when you run them. The CVEFuzz CLI does not run them automatically.

```powershell
$projectRoot = 'C:\path to\cvefuzzer'
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
$databasePath = Join-Path $projectRoot '.cvefuzz\scans.sqlite3'
$reportPath = Join-Path $projectRoot '.cvefuzz\scheduled-refresh.json'
$taskArguments = '-m cvefuzz refresh --all --min-age-hours 24 --database "{0}" --output "{1}" --fail-on never' -f $databasePath, $reportPath
$action = New-ScheduledTaskAction -Execute $pythonPath -Argument $taskArguments -WorkingDirectory $projectRoot
$trigger = New-ScheduledTaskTrigger -Daily -At '03:00'
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName 'CVEFuzz advisory refresh' -Action $action -Trigger $trigger -Settings $settings -Principal $principal
```

Use a distinct task name or edit the existing task if one is already registered. The example does not force replacement of an existing task. Daily activation plus a 24-hour freshness gate means a delayed successful run may cause the next day's early activation to skip; set a shorter query interval if that is undesirable. Increase the one-hour execution limit for large inventories after measuring their runtime.

Inspect the result, run on demand, or remove the task:

```powershell
Get-ScheduledTaskInfo -TaskName 'CVEFuzz advisory refresh'
Start-ScheduledTask -TaskName 'CVEFuzz advisory refresh'
Unregister-ScheduledTask -TaskName 'CVEFuzz advisory refresh'
```

`LastTaskResult` 0/1/2 follows the CLI policy above when Python ran and exited normally; other values may come from Task Scheduler or process termination. Review Task Scheduler history and the report timestamp when diagnosing a run.

References: Microsoft documents [actions and working directories](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskaction), [daily triggers](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger), [overlap and execution limits](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset), [task principals](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal), and [registration](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask).

## Linux systemd user timer

This recipe requires systemd user services and an installed CVEFuzz Python environment. Linux execution and timer activation have not been validated in the Windows development environment. Replace `/home/alice/cvefuzzer` with your own absolute path, including in the executable and database arguments. Quote paths containing spaces in unit command arguments as documented by systemd.

Create `~/.config/systemd/user/cvefuzz-refresh.service`:

```ini
[Unit]
Description=Refresh CVEFuzz saved dependency inventories

[Service]
Type=oneshot
WorkingDirectory=/home/alice/cvefuzzer
ExecStart=/home/alice/cvefuzzer/.venv/bin/python -m cvefuzz refresh --all --min-age-hours 24 --database /home/alice/cvefuzzer/.cvefuzz/scans.sqlite3 --output /home/alice/cvefuzzer/.cvefuzz/scheduled-refresh.json --fail-on never
TimeoutStartSec=1h
```

Create `~/.config/systemd/user/cvefuzz-refresh.timer`:

```ini
[Unit]
Description=Check CVEFuzz refresh intervals hourly

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
```

Enable the timer after creating the files, then inspect it:

```sh
systemctl --user daemon-reload
systemctl --user enable --now cvefuzz-refresh.timer
systemctl --user list-timers cvefuzz-refresh.timer
systemctl --user status cvefuzz-refresh.service
journalctl --user -u cvefuzz-refresh.service
```

The timer checks hourly; each project's saved cache determines whether a provider query is due. Systemd leaves an already active service running instead of starting another instance of that same service. `Persistent=true` can catch a missed calendar activation when the timer is next active; it does not ensure that the user manager runs while logged out. A user-manager lingering policy is a separate machine configuration. `TimeoutStartSec` bounds this one-shot run; size it for your project inventory. No additional success exit status is configured: with `--fail-on never`, operational exit 2 remains a service failure.

Disable future activation and stop any active run:

```sh
systemctl --user disable --now cvefuzz-refresh.timer
systemctl --user stop cvefuzz-refresh.service
```

The unit files and saved database remain for inspection. References: systemd documents [timers, persistence, and overlapping activation](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html), [one-shot services and startup timeouts](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html), and [working directories](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
