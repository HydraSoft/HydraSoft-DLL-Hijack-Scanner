<?php
declare(strict_types=1);

use RobberRemote\App;

require dirname(__DIR__) . '/src/Support.php';
require dirname(__DIR__) . '/src/App.php';

$requireHttpsValue = getenv('REQUIRE_HTTPS');
$trustProxyValue = getenv('TRUST_PROXY');
$requireHttps = filter_var(
    $requireHttpsValue === false ? '1' : $requireHttpsValue,
    FILTER_VALIDATE_BOOL
);
$trustProxy = filter_var(
    $trustProxyValue === false ? '0' : $trustProxyValue,
    FILTER_VALIDATE_BOOL
);
$forwardedProto = $trustProxy
    ? strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))
    : '';
$isHttps = ($_SERVER['HTTPS'] ?? '') === 'on' || ($trustProxy && $forwardedProto === 'https');
if ($requireHttps && !$isHttps) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo '{"error":"HTTPS is required"}';
    exit;
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$accept = strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? ''));
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET'
    && $path === '/'
    && str_contains($accept, 'text/html')) {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    readfile(__DIR__ . '/dashboard.html');
    exit;
}

$dsn = getenv('DB_DSN') ?: 'mysql:host=127.0.0.1;dbname=hydrapanel;charset=utf8mb4';
$db = new PDO($dsn, getenv('DB_USER') ?: '', getenv('DB_PASSWORD') ?: '', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::ATTR_TIMEOUT => max(1, (int)(getenv('DB_TIMEOUT_SECONDS') ?: 5)),
    PDO::MYSQL_ATTR_COMPRESS => true,
]);
$db->exec("SET time_zone = '+00:00'");

$app = new App(
    $db,
    getenv('ADMIN_API_KEY') ?: '',
    max(30, (int)(getenv('JOB_LEASE_SECONDS') ?: 120)),
    max(1024, (int)(getenv('MAX_REPORT_BYTES') ?: 10_485_760)),
);
$app->run($_SERVER['REQUEST_METHOD'] ?? 'GET', $path, $_SERVER, file_get_contents('php://input') ?: '');
