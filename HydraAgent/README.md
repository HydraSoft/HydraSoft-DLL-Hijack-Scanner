# HydraAgent

`HydraAgent.exe` reads `HydraAgent.json` from the same directory as the executable.
Runtime state is stored in `%ProgramData%\HydraAgent`:

- `credential.bin` — DPAPI-protected server credential;
- `startup-report.json` — completed startup scan waiting for upload;
- `startup-scan.complete` — marker preventing repeated startup scans.

On the first launch the agent:

1. scans the path configured in `startup_scan`;
2. stores the report locally;
3. enrolls with `bootstrap_token` when no saved credential exists;
4. uploads the startup report and becomes available for queued commands.

The server request flow is asynchronous. The server queues a command, the agent
claims it during polling, performs the scan locally, then uploads the result in a
separate request.

Run modes:

- double-click or `HydraAgent.exe --console` — interactive agent;
- `HydraAgent.exe --run-once` — one startup/poll cycle;
- no arguments under the Windows Service Control Manager — `HydraAgent` service.
