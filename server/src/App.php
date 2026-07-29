<?php
declare(strict_types=1);

namespace RobberRemote;

use InvalidArgumentException;
use PDO;
use PDOException;
use Throwable;

final class HttpError extends \RuntimeException
{
    public function __construct(public readonly int $status, string $message)
    {
        parent::__construct($message);
    }
}

final class App
{
    public function __construct(
        private readonly PDO $db,
        private readonly string $adminApiKey,
        private readonly int $leaseSeconds = 120,
        private readonly int $maxReportBytes = 10_485_760,
    ) {}

    public function run(string $method, string $path, array $server, string $rawBody): void
    {
        try {
            $this->enforceRateLimit($path, $server);
            if (strlen($rawBody) > $this->maxReportBytes) {
                throw new HttpError(413, 'Request body is too large');
            }
            $body = $rawBody === '' ? [] : json_decode($rawBody, true, 64, JSON_THROW_ON_ERROR);
            if (!is_array($body)) {
                throw new HttpError(400, 'JSON object required');
            }
            $payload = $this->dispatch(strtoupper($method), rtrim($path, '/') ?: '/', $server, $body);
            $this->respond(200, $payload);
        } catch (HttpError $e) {
            $this->respond($e->status, ['error' => $e->getMessage()]);
        } catch (InvalidArgumentException|\JsonException $e) {
            $this->respond(422, ['error' => $e->getMessage()]);
        } catch (Throwable $e) {
            error_log('Robber API error: ' . get_class($e) . ': ' . $e->getMessage());
            $this->respond(500, ['error' => 'Internal server error']);
        }
    }

    private function enforceRateLimit(string $path, array $server): void
    {
        $scope = str_contains($path, '/admin/') ? 'admin'
            : ($path === '/api/v1/agent/enroll' ? 'enroll' : 'agent');
        $bearer = Support::bearerToken($server);
        $identity = $bearer === null
            ? (string)($server['REMOTE_ADDR'] ?? 'unknown')
            : hash('sha256', $bearer);
        $key = hash('sha256', $scope . '|' . $identity, true);
        $limit = $scope === 'enroll' ? 20 : 300;
        $stmt = $this->db->prepare(
            'INSERT INTO robber_api_rate_limits (rate_key, window_started_at, request_count)
             VALUES (?, UTC_TIMESTAMP(3), 1)
             ON DUPLICATE KEY UPDATE
               request_count = IF(window_started_at < DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 1 MINUTE),
                 1, request_count + 1),
               window_started_at = IF(window_started_at < DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 1 MINUTE),
                 UTC_TIMESTAMP(3), window_started_at)'
        );
        $stmt->bindValue(1, $key, PDO::PARAM_LOB);
        $stmt->execute();
        $check = $this->db->prepare(
            'SELECT request_count FROM robber_api_rate_limits WHERE rate_key = ?'
        );
        $check->bindValue(1, $key, PDO::PARAM_LOB);
        $check->execute();
        if ((int)$check->fetchColumn() > $limit) {
            throw new HttpError(429, 'Rate limit exceeded');
        }
    }

    private function dispatch(string $method, string $path, array $server, array $body): array
    {
        if ($method === 'GET' && $path === '/') {
            return [
                'service' => 'Robber Remote API',
                'status' => 'ok',
                'health' => '/health',
                'api_version' => 'v1',
            ];
        }
        if ($method === 'GET' && $path === '/health') {
            return ['ok' => true];
        }
        if ($method === 'POST' && $path === '/api/v1/agent/enroll') {
            return $this->enroll($body);
        }

        if (str_starts_with($path, '/api/v1/agent/')) {
            $agent = $this->requireAgent($server);
            if ($method === 'POST' && $path === '/api/v1/agent/jobs/claim') {
                return $this->claim((int)$agent['id']);
            }
            if ($method === 'POST' && $path === '/api/v1/agent/reports/startup') {
                return $this->storeStartupReport($agent, $body);
            }
            if ($method === 'POST'
                && preg_match('#^/api/v1/agent/jobs/(\d+)/(heartbeat|complete|fail)$#D', $path, $match)) {
                return $this->agentJobAction((int)$agent['id'], (int)$match[1], $match[2], $body);
            }
            throw new HttpError(404, 'Agent endpoint not found');
        }

        if (str_starts_with($path, '/api/v1/admin/')) {
            $this->requireAdmin($server);
            if ($method === 'GET' && $path === '/api/v1/admin/agents') {
                return ['agents' => $this->db->query(
                    'SELECT id, ad_stats_id, computer_name, agent_version, status, enrolled_at, last_seen_at
                     FROM robber_agents ORDER BY id DESC'
                )->fetchAll()];
            }
            if ($method === 'POST' && $path === '/api/v1/admin/agents/lookup') {
                return $this->lookupAgentByToken($body);
            }
            if ($method === 'POST' && $path === '/api/v1/admin/jobs') {
                return $this->createJob($body);
            }
            if ($method === 'GET'
                && preg_match('#^/api/v1/admin/agents/(\d+)/reports/latest$#D', $path, $match)) {
                return $this->getLatestAgentReport((int)$match[1]);
            }
            if (preg_match('#^/api/v1/admin/jobs/(\d+)$#D', $path, $match)) {
                if ($method === 'DELETE') {
                    return $this->cancelJob((int)$match[1]);
                }
                if ($method === 'GET') {
                    return $this->getJob((int)$match[1]);
                }
                throw new HttpError(405, 'Method not allowed');
            }
            if ($method === 'GET' && preg_match('#^/api/v1/admin/reports/(\d+)$#D', $path, $match)) {
                return $this->getReport((int)$match[1]);
            }
            throw new HttpError(404, 'Admin endpoint not found');
        }
        throw new HttpError(404, 'Endpoint not found');
    }

    private function enroll(array $body): array
    {
        $hex = Support::normalizeBootstrapToken((string)($body['bootstrap_token'] ?? ''));
        $computerName = trim((string)($body['computer_name'] ?? ''));
        $agentVersion = trim((string)($body['agent_version'] ?? ''));
        if ($computerName === '' || strlen($computerName) > 128
            || $agentVersion === '' || strlen($agentVersion) > 64) {
            throw new HttpError(422, 'computer_name and agent_version are required');
        }

        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare('SELECT id FROM ad_stats WHERE record_token = UNHEX(?) FOR UPDATE');
            $stmt->execute([$hex]);
            $adStatsId = $stmt->fetchColumn();
            if ($adStatsId === false) {
                throw new HttpError(401, 'Unknown bootstrap token');
            }
            $stmt = $this->db->prepare('SELECT id FROM robber_agents WHERE ad_stats_id = ?');
            $stmt->execute([$adStatsId]);
            if ($stmt->fetchColumn() !== false) {
                throw new HttpError(409, 'Bootstrap token has already been used');
            }

            $credential = Support::generateCredential();
            $stmt = $this->db->prepare(
                'INSERT INTO robber_agents
                    (ad_stats_id, credential_hash, computer_name, agent_version, status, last_seen_at)
                 VALUES (?, ?, ?, ?, "ONLINE", UTC_TIMESTAMP(3))'
            );
            $hash = Support::credentialHash($credential);
            $stmt->bindValue(1, $adStatsId, PDO::PARAM_INT);
            $stmt->bindValue(2, $hash, PDO::PARAM_LOB);
            $stmt->bindValue(3, $computerName);
            $stmt->bindValue(4, $agentVersion);
            $stmt->execute();
            $agentId = (int)$this->db->lastInsertId();
            $this->db->commit();
            return ['agent_id' => $agentId, 'credential' => $credential, 'poll_after_seconds' => 15];
        } catch (Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }

    private function requireAgent(array $server): array
    {
        $credential = Support::bearerToken($server);
        if ($credential === null) {
            throw new HttpError(401, 'Bearer credential required');
        }
        try {
            $hash = Support::credentialHash($credential);
        } catch (InvalidArgumentException) {
            throw new HttpError(401, 'Invalid agent credential');
        }
        $stmt = $this->db->prepare(
            'SELECT id, ad_stats_id FROM robber_agents
             WHERE credential_hash = ? AND status <> "DISABLED" LIMIT 1'
        );
        $stmt->bindValue(1, $hash, PDO::PARAM_LOB);
        $stmt->execute();
        $agent = $stmt->fetch();
        if (!$agent) {
            throw new HttpError(401, 'Invalid agent credential');
        }
        $touch = $this->db->prepare(
            'UPDATE robber_agents SET status = "ONLINE", last_seen_at = UTC_TIMESTAMP(3) WHERE id = ?'
        );
        $touch->execute([$agent['id']]);
        return $agent;
    }

    private function requireAdmin(array $server): void
    {
        $token = Support::bearerToken($server);
        if ($this->adminApiKey === '' || $token === null || !hash_equals($this->adminApiKey, $token)) {
            throw new HttpError(401, 'Admin API key required');
        }
    }

    private function claim(int $agentId): array
    {
        $this->db->beginTransaction();
        try {
            $reset = $this->db->prepare(
                'UPDATE robber_jobs SET status = "QUEUED", lease_until = NULL
                 WHERE agent_id = ? AND status IN ("LEASED","RUNNING")
                   AND lease_until < UTC_TIMESTAMP(3)'
            );
            $reset->execute([$agentId]);

            $stmt = $this->db->prepare(
                'SELECT id, operation, params_json FROM robber_jobs
                 WHERE agent_id = ? AND status = "QUEUED"
                 ORDER BY created_at, id LIMIT 1 FOR UPDATE'
            );
            $stmt->execute([$agentId]);
            $job = $stmt->fetch();
            if (!$job) {
                $this->db->commit();
                return ['job' => null, 'poll_after_seconds' => 15];
            }
            $update = $this->db->prepare(
                'UPDATE robber_jobs
                 SET status = "LEASED", lease_until = DATE_ADD(UTC_TIMESTAMP(3), INTERVAL ? SECOND)
                 WHERE id = ? AND status = "QUEUED"'
            );
            $update->execute([$this->leaseSeconds, $job['id']]);
            $this->db->commit();
            return ['job' => [
                'id' => (int)$job['id'],
                'operation' => $job['operation'],
                'params' => json_decode($job['params_json'], true, 32, JSON_THROW_ON_ERROR),
                'lease_seconds' => $this->leaseSeconds,
            ]];
        } catch (Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }

    private function agentJobAction(int $agentId, int $jobId, string $action, array $body): array
    {
        if ($action === 'heartbeat') {
            $stmt = $this->db->prepare(
                'UPDATE robber_jobs SET status = "RUNNING",
                    started_at = COALESCE(started_at, UTC_TIMESTAMP(3)),
                    heartbeat_at = UTC_TIMESTAMP(3),
                    lease_until = DATE_ADD(UTC_TIMESTAMP(3), INTERVAL ? SECOND)
                 WHERE id = ? AND agent_id = ? AND status IN ("LEASED","RUNNING")'
            );
            $stmt->execute([$this->leaseSeconds, $jobId, $agentId]);
            if ($stmt->rowCount() === 1) {
                return ['ok' => true, 'cancelled' => false];
            }
            $status = $this->db->prepare(
                'SELECT status FROM robber_jobs WHERE id = ? AND agent_id = ?'
            );
            $status->execute([$jobId, $agentId]);
            if ($status->fetchColumn() === 'CANCELLED') {
                return ['ok' => true, 'cancelled' => true];
            }
            throw new HttpError(409, 'Job is not active for this agent');
        }

        if ($action === 'fail') {
            $code = substr((string)($body['error_code'] ?? 'AGENT_ERROR'), 0, 64);
            $message = substr((string)($body['error_message'] ?? ''), 0, 1024);
            $stmt = $this->db->prepare(
                'UPDATE robber_jobs SET status = "FAILED", completed_at = UTC_TIMESTAMP(3),
                    lease_until = NULL, error_code = ?, error_message = ?
                 WHERE id = ? AND agent_id = ? AND status IN ("LEASED","RUNNING")'
            );
            $stmt->execute([$code, $message, $jobId, $agentId]);
            if ($stmt->rowCount() !== 1) {
                throw new HttpError(409, 'Job cannot be failed');
            }
            return ['ok' => true];
        }

        $report = $body['report'] ?? null;
        $summary = $body['summary'] ?? null;
        if (!is_array($report) || ($summary !== null && !is_array($summary))) {
            throw new HttpError(422, 'report must be a JSON object');
        }
        $reportJson = json_encode($report, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $summaryJson = $summary === null ? null : json_encode($summary, JSON_THROW_ON_ERROR);
        $hash = hash('sha256', $reportJson, true);

        $this->db->beginTransaction();
        try {
            $jobStmt = $this->db->prepare(
                'SELECT j.status, a.ad_stats_id
                 FROM robber_jobs j JOIN robber_agents a ON a.id = j.agent_id
                 WHERE j.id = ? AND j.agent_id = ? FOR UPDATE'
            );
            $jobStmt->execute([$jobId, $agentId]);
            $job = $jobStmt->fetch();
            if (!$job) {
                throw new HttpError(404, 'Job not found');
            }
            $existing = $this->db->prepare('SELECT content_sha256 FROM robber_reports WHERE job_id = ?');
            $existing->execute([$jobId]);
            $existingHash = $existing->fetchColumn();
            if ($existingHash !== false) {
                if (!hash_equals($existingHash, $hash)) {
                    throw new HttpError(409, 'A different report is already stored');
                }
                $this->db->commit();
                return ['ok' => true, 'duplicate' => true];
            }
            if (!in_array($job['status'], ['LEASED', 'RUNNING'], true)) {
                throw new HttpError(409, 'Job is not active');
            }
            $insert = $this->db->prepare(
                'INSERT INTO robber_reports
                    (job_id, agent_id, ad_stats_id, report_json, summary_json, content_sha256)
                 VALUES (?, ?, ?, ?, ?, ?)'
            );
            $insert->bindValue(1, $jobId, PDO::PARAM_INT);
            $insert->bindValue(2, $agentId, PDO::PARAM_INT);
            $insert->bindValue(3, $job['ad_stats_id'], PDO::PARAM_INT);
            $insert->bindValue(4, $reportJson);
            $insert->bindValue(5, $summaryJson);
            $insert->bindValue(6, $hash, PDO::PARAM_LOB);
            $insert->execute();
            $done = $this->db->prepare(
                'UPDATE robber_jobs SET status = "COMPLETE", completed_at = UTC_TIMESTAMP(3),
                    lease_until = NULL WHERE id = ?'
            );
            $done->execute([$jobId]);
            $adComplete = $this->db->prepare(
                'UPDATE ad_stats SET status = "COMPLETE" WHERE id = ?'
            );
            $adComplete->execute([$job['ad_stats_id']]);
            $this->db->commit();
            return ['ok' => true, 'duplicate' => false];
        } catch (Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }

    private function storeStartupReport(array $agent, array $body): array
    {
        $report = $body['report'] ?? null;
        $summary = $body['summary'] ?? null;
        if (!is_array($report) || ($summary !== null && !is_array($summary))) {
            throw new HttpError(422, 'report must be a JSON object');
        }
        $reportJson = json_encode(
            $report,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );
        $summaryJson = $summary === null ? null : json_encode($summary, JSON_THROW_ON_ERROR);
        $hash = hash('sha256', $reportJson, true);
        $agentId = (int)$agent['id'];
        $adStatsId = (int)$agent['ad_stats_id'];
        $agentVersion = trim((string)($report['agentVersion'] ?? ''));
        if ($agentVersion === '' || strlen($agentVersion) > 64) {
            throw new HttpError(422, 'report.agentVersion is required');
        }

        $this->db->beginTransaction();
        try {
            $version = $this->db->prepare(
                'UPDATE robber_agents
                 SET agent_version = ?, status = "ONLINE", last_seen_at = UTC_TIMESTAMP(3)
                 WHERE id = ?'
            );
            $version->execute([$agentVersion, $agentId]);
            $existing = $this->db->prepare(
                'SELECT job_id FROM robber_reports
                 WHERE agent_id = ? AND content_sha256 = ? ORDER BY id DESC LIMIT 1'
            );
            $existing->bindValue(1, $agentId, PDO::PARAM_INT);
            $existing->bindValue(2, $hash, PDO::PARAM_LOB);
            $existing->execute();
            $existingJobId = $existing->fetchColumn();
            if ($existingJobId !== false) {
                $this->db->commit();
                return ['ok' => true, 'duplicate' => true, 'job_id' => (int)$existingJobId];
            }

            $job = $this->db->prepare(
                'INSERT INTO robber_jobs
                    (agent_id, operation, params_json, status, started_at, completed_at)
                 VALUES (?, "hydra.startup-scan", ?, "COMPLETE", UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))'
            );
            $job->execute([
                $agentId,
                json_encode(['startup' => true, 'path' => $report['scanPath'] ?? null], JSON_THROW_ON_ERROR),
            ]);
            $jobId = (int)$this->db->lastInsertId();

            $insert = $this->db->prepare(
                'INSERT INTO robber_reports
                    (job_id, agent_id, ad_stats_id, report_json, summary_json, content_sha256)
                 VALUES (?, ?, ?, ?, ?, ?)'
            );
            $insert->bindValue(1, $jobId, PDO::PARAM_INT);
            $insert->bindValue(2, $agentId, PDO::PARAM_INT);
            $insert->bindValue(3, $adStatsId, PDO::PARAM_INT);
            $insert->bindValue(4, $reportJson);
            $insert->bindValue(5, $summaryJson);
            $insert->bindValue(6, $hash, PDO::PARAM_LOB);
            $insert->execute();
            $complete = $this->db->prepare('UPDATE ad_stats SET status = "COMPLETE" WHERE id = ?');
            $complete->execute([$adStatsId]);
            $this->db->commit();
            return ['ok' => true, 'duplicate' => false, 'job_id' => $jobId];
        } catch (Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }

    private function createJob(array $body): array
    {
        $agentId = filter_var($body['agent_id'] ?? null, FILTER_VALIDATE_INT);
        if (!$agentId || $agentId < 1) {
            throw new HttpError(422, 'agent_id is required');
        }
        $operation = (string)($body['operation'] ?? '');
        $params = Support::validateOperation($operation, is_array($body['params'] ?? null) ? $body['params'] : []);
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare(
                'INSERT INTO robber_jobs (agent_id, operation, params_json) VALUES (?, ?, ?)'
            );
            $stmt->execute([$agentId, $operation, json_encode($params, JSON_THROW_ON_ERROR)]);
            $jobId = (int)$this->db->lastInsertId();
            $status = $this->db->prepare(
                'UPDATE ad_stats s JOIN robber_agents a ON a.ad_stats_id = s.id
                 SET s.status = "REQUEST" WHERE a.id = ?'
            );
            $status->execute([$agentId]);
            $this->db->commit();
        } catch (Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            if ($e instanceof PDOException && $e->getCode() === '23000') {
                throw new HttpError(422, 'Unknown agent');
            }
            throw $e;
        }
        return ['job_id' => $jobId, 'status' => 'QUEUED'];
    }

    private function lookupAgentByToken(array $body): array
    {
        $hex = Support::normalizeBootstrapToken((string)($body['record_token'] ?? ''));
        $stmt = $this->db->prepare(
            'SELECT a.id, a.ad_stats_id, a.computer_name, a.agent_version, a.status,
                    a.enrolled_at, a.last_seen_at
             FROM robber_agents a
             JOIN ad_stats s ON s.id = a.ad_stats_id
             WHERE s.record_token = UNHEX(?) LIMIT 1'
        );
        $stmt->execute([$hex]);
        $agent = $stmt->fetch();
        if (!$agent) {
            throw new HttpError(404, 'Agent for record_token was not found');
        }
        return ['agents' => [$agent]];
    }

    private function getJob(int $jobId): array
    {
        $stmt = $this->db->prepare(
            'SELECT id, agent_id, operation, params_json, status, lease_until, heartbeat_at,
                    started_at, completed_at, error_code, error_message, created_at
             FROM robber_jobs WHERE id = ?'
        );
        $stmt->execute([$jobId]);
        $job = $stmt->fetch();
        if (!$job) {
            throw new HttpError(404, 'Job not found');
        }
        $job['id'] = (int)$job['id'];
        $job['agent_id'] = (int)$job['agent_id'];
        $job['params'] = json_decode($job['params_json'], true);
        unset($job['params_json']);
        return ['job' => $job];
    }

    private function cancelJob(int $jobId): array
    {
        $stmt = $this->db->prepare(
            'UPDATE robber_jobs SET status = "CANCELLED", completed_at = UTC_TIMESTAMP(3),
                lease_until = NULL WHERE id = ? AND status IN ("QUEUED","LEASED","RUNNING")'
        );
        $stmt->execute([$jobId]);
        if ($stmt->rowCount() !== 1) {
            throw new HttpError(409, 'Only active jobs can be cancelled');
        }
        return ['ok' => true];
    }

    private function getLatestAgentReport(int $agentId): array
    {
        $stmt = $this->db->prepare(
            'SELECT job_id FROM robber_reports
             WHERE agent_id = ? ORDER BY created_at DESC, id DESC LIMIT 1'
        );
        $stmt->execute([$agentId]);
        $jobId = $stmt->fetchColumn();
        if ($jobId === false) {
            throw new HttpError(404, 'Report not found');
        }
        return $this->getReport((int)$jobId);
    }

    private function getReport(int $jobId): array
    {
        $offset = max(0, filter_input(INPUT_GET, 'offset', FILTER_VALIDATE_INT) ?: 0);
        $limit = filter_input(INPUT_GET, 'limit', FILTER_VALIDATE_INT) ?: 10;
        $limit = max(1, min(10, $limit));
        $end = $offset + $limit - 1;
        $resultsPath = '$.results[' . $offset . ' to ' . $end . ']';
        $stmt = $this->db->prepare(
            'SELECT id, job_id, agent_id, ad_stats_id, summary_json,
                    HEX(content_sha256) AS content_sha256, created_at,
                    JSON_LENGTH(report_json, "$.results") AS total_results,
                    JSON_UNQUOTE(JSON_EXTRACT(report_json, "$.agentVersion")) AS agent_version,
                    JSON_UNQUOTE(JSON_EXTRACT(report_json, "$.computerName")) AS computer_name,
                    JSON_UNQUOTE(JSON_EXTRACT(report_json, "$.scanPath")) AS scan_path,
                    JSON_UNQUOTE(JSON_EXTRACT(report_json, "$.startedAt")) AS started_at,
                    JSON_UNQUOTE(JSON_EXTRACT(report_json, "$.finishedAt")) AS finished_at,
                    JSON_EXTRACT(report_json, "$.summary") AS report_summary_json,
                    JSON_EXTRACT(report_json, ?) AS results_json
             FROM robber_reports WHERE job_id = ?'
        );
        $stmt->execute([$resultsPath, $jobId]);
        $report = $stmt->fetch();
        if (!$report) {
            throw new HttpError(404, 'Report not found');
        }
        $report['report'] = [
            'agentId' => (int)$report['agent_id'],
            'agentVersion' => $report['agent_version'],
            'computerName' => $report['computer_name'],
            'scanPath' => $report['scan_path'],
            'startedAt' => $report['started_at'],
            'finishedAt' => $report['finished_at'],
            'summary' => json_decode($report['report_summary_json'], true),
            'results' => $report['results_json'] === null
                ? [] : (json_decode($report['results_json'], true) ?? []),
        ];
        $report['summary'] = $report['summary_json'] === null
            ? null : json_decode($report['summary_json'], true);
        $report['pagination'] = [
            'offset' => $offset,
            'limit' => $limit,
            'total' => (int)$report['total_results'],
        ];
        unset(
            $report['summary_json'], $report['total_results'], $report['agent_version'],
            $report['computer_name'], $report['scan_path'], $report['started_at'],
            $report['finished_at'], $report['report_summary_json'], $report['results_json']
        );
        return ['report' => $report];
    }

    private function respond(int $status, array $payload): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
}
