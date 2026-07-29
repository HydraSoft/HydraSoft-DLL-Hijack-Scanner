# Robber Remote API

Minimal PHP 8.2 and MySQL API for the Robber Windows agent.

## Deploy

1. Apply `migrations/001_robber_remote.sql` to the same MySQL 8 database that
   contains `ad_stats`.
2. Point the HTTPS virtual host document root at `server/public`.
3. Route every request to `public/index.php`.
4. Set environment variables:

```text
DB_DSN=mysql:host=127.0.0.1;dbname=hydrapanel;charset=utf8mb4
DB_USER=hydrapanel
DB_PASSWORD=change-me
ADMIN_API_KEY=generate-at-least-32-random-bytes
REQUIRE_HTTPS=1
TRUST_PROXY=1
JOB_LEASE_SECONDS=120
MAX_REPORT_BYTES=10485760
```

Set `TRUST_PROXY=1` only when PHP is reachable exclusively through the reverse
proxy. The proxy must replace, rather than append, `X-Forwarded-Proto`.
Credentials and bootstrap tokens must not be included in HTTP access logs.

## Agent provisioning

Place these files in `%ProgramData%\RobberAgent` before starting the service:

- `agent.json`, based on `RobberAgent/agent.example.json`;
- `bootstrap.token`, containing `0x` followed by 32 hexadecimal characters.

After enrollment the agent stores its generated credential with machine-scoped
Windows DPAPI and deletes `bootstrap.token`. Reuse of the corresponding
`ad_stats.record_token` is rejected.

Install the built agent from an elevated terminal:

```powershell
sc.exe create RobberAgent binPath= "C:\Program Files\RobberAgent\RobberAgent.exe" start= auto
sc.exe start RobberAgent
```

For a foreground smoke test, run `RobberAgent.exe --run-once`.

## Admin API

Use `Authorization: Bearer <ADMIN_API_KEY>`.

- `GET /api/v1/admin/agents`
- `POST /api/v1/admin/jobs`
- `GET /api/v1/admin/jobs/{id}`
- `DELETE /api/v1/admin/jobs/{id}`
- `GET /api/v1/admin/reports/{job_id}`

Example job:

```json
{
  "agent_id": 1,
  "operation": "robber.scan",
  "params": {
    "path": "C:\\Program Files",
    "image_type": "any",
    "sign": "any",
    "rate": "any",
    "write_perm": false,
    "best_dll_count": 2,
    "best_exe_size": 10240,
    "good_dll_count": 5,
    "good_exe_size": 51200
  }
}
```

Only operations registered by both the server and agent are accepted. The MVP
does not expose shell or arbitrary process execution.
