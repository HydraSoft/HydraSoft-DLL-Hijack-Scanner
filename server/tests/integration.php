<?php
declare(strict_types=1);

use RobberRemote\App;

require dirname(__DIR__) . '/src/Support.php';
require dirname(__DIR__) . '/src/App.php';

$dsn = getenv('TEST_DB_DSN');
if (!$dsn) {
    fwrite(STDERR, "Skipped: set TEST_DB_DSN, TEST_DB_USER and TEST_DB_PASSWORD\n");
    exit(0);
}

$db = new PDO($dsn, getenv('TEST_DB_USER') ?: '', getenv('TEST_DB_PASSWORD') ?: '', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::MYSQL_ATTR_COMPRESS => true,
]);
$adminKey = 'integration-admin-key-with-at-least-32-bytes';
$app = new App($db, $adminKey, 60, 1024 * 1024);

function request(App $app, string $method, string $path, array $server, array $body = []): array
{
    http_response_code(200);
    ob_start();
    $app->run($method, $path, $server, $body === [] ? '' : json_encode($body, JSON_THROW_ON_ERROR));
    $json = json_decode((string)ob_get_clean(), true, 64, JSON_THROW_ON_ERROR);
    return [http_response_code(), $json];
}

function assertStatus(array $response, int $status): array
{
    if ($response[0] !== $status) {
        throw new RuntimeException("Expected HTTP {$status}, got {$response[0]}: " . json_encode($response[1]));
    }
    return $response[1];
}

$tokenHex = bin2hex(random_bytes(16));
$adStatsId = null;
$agentId = null;
$jobId = null;
$startupJobId = null;
$cancelledJobId = null;

try {
    $stmt = $db->prepare(
        'INSERT INTO ad_stats
            (record_token, status, ip, user_agent, created_at, status_updated_at)
         VALUES
            (UNHEX(?), "INSTALL", "127.0.0.1", "Hydra integration test",
             UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))'
    );
    $stmt->execute([$tokenHex]);
    $adStatsId = (int)$db->lastInsertId();

    $enrollment = assertStatus(request($app, 'POST', '/api/v1/agent/enroll', [], [
        'bootstrap_token' => '0x' . $tokenHex,
        'computer_name' => 'INTEGRATION-PC',
        'agent_version' => 'test',
    ]), 200);
    $agentId = (int)$enrollment['agent_id'];
    $agentAuth = ['HTTP_AUTHORIZATION' => 'Bearer ' . $enrollment['credential']];
    $adminAuth = ['HTTP_AUTHORIZATION' => 'Bearer ' . $adminKey];

    assertStatus(request($app, 'POST', '/api/v1/agent/enroll', [], [
        'bootstrap_token' => '0x' . $tokenHex,
        'computer_name' => 'INTEGRATION-PC',
        'agent_version' => 'test',
    ]), 409);
    assertStatus(request($app, 'POST', '/api/v1/agent/jobs/claim', [
        'HTTP_AUTHORIZATION' => 'Bearer invalid',
    ]), 401);

    $created = assertStatus(request($app, 'POST', '/api/v1/admin/jobs', $adminAuth, [
        'agent_id' => $agentId,
        'operation' => 'robber.scan',
        'params' => ['path' => 'C:\\Program Files'],
    ]), 200);
    $jobId = (int)$created['job_id'];
    $statusStmt = $db->prepare('SELECT status FROM ad_stats WHERE id = ?');
    $statusStmt->execute([$adStatsId]);
    if ($statusStmt->fetchColumn() !== 'REQUEST') {
        throw new RuntimeException('ad_stats was not moved to REQUEST');
    }

    $claimed = assertStatus(request(
        $app, 'POST', '/api/v1/agent/jobs/claim', $agentAuth
    ), 200);
    if ((int)$claimed['job']['id'] !== $jobId) {
        throw new RuntimeException('The wrong job was claimed');
    }
    assertStatus(request(
        $app, 'POST', "/api/v1/agent/jobs/{$jobId}/heartbeat", $agentAuth
    ), 200);

    $completion = [
        'report' => [
            'schemaVersion' => 1,
            'jobId' => $jobId,
            'results' => [],
        ],
        'summary' => ['vulnerableExecutables' => 0],
    ];
    assertStatus(request(
        $app, 'POST', "/api/v1/agent/jobs/{$jobId}/complete", $agentAuth, $completion
    ), 200);
    $statusStmt->execute([$adStatsId]);
    if ($statusStmt->fetchColumn() !== 'COMPLETE') {
        throw new RuntimeException('ad_stats was not moved to COMPLETE');
    }
    $duplicate = assertStatus(request(
        $app, 'POST', "/api/v1/agent/jobs/{$jobId}/complete", $agentAuth, $completion
    ), 200);
    if (!$duplicate['duplicate']) {
        throw new RuntimeException('Idempotent completion was not detected');
    }

    $report = assertStatus(request(
        $app, 'GET', "/api/v1/admin/reports/{$jobId}", $adminAuth
    ), 200);
    if ((int)$report['report']['ad_stats_id'] !== $adStatsId) {
        throw new RuntimeException('Report is linked to the wrong ad_stats row');
    }

    $startupCompletion = [
        'report' => [
            'schemaVersion' => 1,
            'jobId' => 0,
            'agentId' => 0,
            'agentVersion' => 'test',
            'computerName' => 'INTEGRATION-PC',
            'scanPath' => 'C:\\',
            'startedAt' => '2026-01-01T00:00:00Z',
            'finishedAt' => '2026-01-01T00:01:00Z',
            'summary' => ['vulnerableExecutables' => 0],
            'results' => [],
        ],
        'summary' => ['vulnerableExecutables' => 0],
    ];
    $startup = assertStatus(request(
        $app, 'POST', '/api/v1/agent/reports/startup', $agentAuth, $startupCompletion
    ), 200);
    $startupJobId = (int)$startup['job_id'];
    $startupDuplicate = assertStatus(request(
        $app, 'POST', '/api/v1/agent/reports/startup', $agentAuth, $startupCompletion
    ), 200);
    if (!$startupDuplicate['duplicate'] || (int)$startupDuplicate['job_id'] !== $startupJobId) {
        throw new RuntimeException('Startup report upload is not idempotent');
    }
    $latest = assertStatus(request(
        $app, 'GET', "/api/v1/admin/agents/{$agentId}/reports/latest", $adminAuth
    ), 200);
    if ((int)$latest['report']['job_id'] !== $startupJobId) {
        throw new RuntimeException('Latest agent report is not the startup report');
    }

    $cancelled = assertStatus(request($app, 'POST', '/api/v1/admin/jobs', $adminAuth, [
        'agent_id' => $agentId,
        'operation' => 'robber.scan',
        'params' => ['path' => 'C:\\Program Files'],
    ]), 200);
    $cancelledJobId = (int)$cancelled['job_id'];
    assertStatus(request($app, 'POST', '/api/v1/agent/jobs/claim', $agentAuth), 200);
    assertStatus(request(
        $app, 'POST', "/api/v1/agent/jobs/{$cancelledJobId}/heartbeat", $agentAuth
    ), 200);
    assertStatus(request(
        $app, 'DELETE', "/api/v1/admin/jobs/{$cancelledJobId}", $adminAuth
    ), 200);
    $cancelHeartbeat = assertStatus(request(
        $app, 'POST', "/api/v1/agent/jobs/{$cancelledJobId}/heartbeat", $agentAuth
    ), 200);
    if (!$cancelHeartbeat['cancelled']) {
        throw new RuntimeException('Cancellation was not delivered through heartbeat');
    }
    echo "Integration flow passed\n";
} finally {
    if ($startupJobId !== null) {
        $db->prepare('DELETE FROM robber_reports WHERE job_id = ?')->execute([$startupJobId]);
        $db->prepare('DELETE FROM robber_jobs WHERE id = ?')->execute([$startupJobId]);
    }
    if ($cancelledJobId !== null) {
        $db->prepare('DELETE FROM robber_jobs WHERE id = ?')->execute([$cancelledJobId]);
    }
    if ($jobId !== null) {
        $db->prepare('DELETE FROM robber_reports WHERE job_id = ?')->execute([$jobId]);
        $db->prepare('DELETE FROM robber_jobs WHERE id = ?')->execute([$jobId]);
    }
    if ($agentId !== null) {
        $db->prepare('DELETE FROM robber_agents WHERE id = ?')->execute([$agentId]);
    }
    if ($adStatsId !== null) {
        $db->prepare('DELETE FROM ad_stats WHERE id = ?')->execute([$adStatsId]);
    }
}
