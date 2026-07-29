<?php
declare(strict_types=1);

function respond(int $status, array $payload): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    respond(405, ['error' => 'Method not allowed']);
}

$requireHttpsValue = getenv('REQUIRE_HTTPS');
$requireHttps = filter_var(
    $requireHttpsValue === false ? '1' : $requireHttpsValue,
    FILTER_VALIDATE_BOOL,
);
$isHttps = ($_SERVER['HTTPS'] ?? '') === 'on';
if ($requireHttps && !$isHttps) {
    respond(400, ['error' => 'HTTPS is required']);
}

$machineGuid = strtolower(trim((string)($_GET['machine_guid'] ?? '')));
if (str_starts_with($machineGuid, '{') && str_ends_with($machineGuid, '}')) {
    $machineGuid = substr($machineGuid, 1, -1);
}
if (!preg_match(
    '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D',
    $machineGuid,
)) {
    respond(422, ['error' => 'machine_guid must be a canonical GUID']);
}

$forwardedFor = trim(explode(',', (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''))[0]);
$remoteAddress = (string)($_SERVER['REMOTE_ADDR'] ?? '');
$ip = filter_var($forwardedFor, FILTER_VALIDATE_IP) ? $forwardedFor : $remoteAddress;
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    $ip = '0.0.0.0';
}
$userAgent = substr(trim((string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 1024);
if ($userAgent === '') {
    $userAgent = 'HydraDLL';
}

$lockName = 'hydra:' . substr(hash('sha256', $machineGuid), 0, 58);
$db = null;
$lockAcquired = false;

try {
    $dsn = getenv('DB_DSN') ?: 'mysql:host=127.0.0.1;dbname=hydrapanel;charset=utf8mb4';
    $db = new PDO($dsn, getenv('DB_USER') ?: '', getenv('DB_PASSWORD') ?: '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_TIMEOUT => max(1, (int)(getenv('DB_TIMEOUT_SECONDS') ?: 5)),
        PDO::MYSQL_ATTR_COMPRESS => true,
    ]);
    $db->exec("SET time_zone = '+00:00'");

    $rateKey = hash('sha256', 'machine-token|' . $ip, true);
    $stmt = $db->prepare(
        'INSERT INTO robber_api_rate_limits (rate_key, window_started_at, request_count)
         VALUES (?, UTC_TIMESTAMP(3), 1)
         ON DUPLICATE KEY UPDATE
           request_count = IF(window_started_at < DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 1 MINUTE),
             1, request_count + 1),
           window_started_at = IF(window_started_at < DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 1 MINUTE),
             UTC_TIMESTAMP(3), window_started_at)'
    );
    $stmt->bindValue(1, $rateKey, PDO::PARAM_LOB);
    $stmt->execute();
    $stmt = $db->prepare(
        'SELECT request_count FROM robber_api_rate_limits WHERE rate_key = ?'
    );
    $stmt->bindValue(1, $rateKey, PDO::PARAM_LOB);
    $stmt->execute();
    if ((int)$stmt->fetchColumn() > 30) {
        respond(429, ['error' => 'Rate limit exceeded']);
    }

    $stmt = $db->prepare('SELECT GET_LOCK(?, 5)');
    $stmt->execute([$lockName]);
    $lockAcquired = (int)$stmt->fetchColumn() === 1;
    if (!$lockAcquired) {
        respond(503, ['error' => 'Registration is busy; retry later']);
    }

    $db->beginTransaction();
    $stmt = $db->prepare(
        'SELECT id, LOWER(HEX(record_token)) AS record_token
         FROM ad_stats
         WHERE machine_guid = ?
         ORDER BY id ASC
         LIMIT 1
         FOR UPDATE'
    );
    $stmt->execute([$machineGuid]);
    $existing = $stmt->fetch();
    if ($existing) {
        $db->commit();
        respond(200, [
            'record_token' => '0x' . $existing['record_token'],
            'created' => false,
        ]);
    }

    $token = random_bytes(16);
    $stmt = $db->prepare(
        'INSERT INTO ad_stats
            (record_token, created_at, status_updated_at, status, ip, user_agent, machine_guid)
         VALUES (?, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3), "INSTALL", ?, ?, ?)'
    );
    $stmt->bindValue(1, $token, PDO::PARAM_LOB);
    $stmt->bindValue(2, $ip);
    $stmt->bindValue(3, $userAgent);
    $stmt->bindValue(4, $machineGuid);
    $stmt->execute();
    $db->commit();

    respond(200, [
        'record_token' => '0x' . bin2hex($token),
        'created' => true,
    ]);
} catch (Throwable $e) {
    if ($db instanceof PDO && $db->inTransaction()) {
        $db->rollBack();
    }
    error_log('Machine token endpoint error: ' . get_class($e) . ': ' . $e->getMessage());
    respond(500, ['error' => 'Internal server error']);
} finally {
    if ($lockAcquired && $db instanceof PDO) {
        try {
            $stmt = $db->prepare('SELECT RELEASE_LOCK(?)');
            $stmt->execute([$lockName]);
        } catch (Throwable) {
        }
    }
}
