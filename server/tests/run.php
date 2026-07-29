<?php
declare(strict_types=1);

use RobberRemote\Support;

require dirname(__DIR__) . '/src/Support.php';

function expect(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function expectInvalid(callable $callback, string $message): void
{
    try {
        $callback();
    } catch (InvalidArgumentException) {
        return;
    }
    throw new RuntimeException($message);
}

expect(
    Support::normalizeBootstrapToken(' 0x11F0EF1A6FF1A35D86E1F61C23066423 ') ===
    '11f0ef1a6ff1a35d86e1f61c23066423',
    'bootstrap token normalization failed'
);
expectInvalid(
    static fn() => Support::normalizeBootstrapToken('0x1234'),
    'short bootstrap token was accepted'
);

$credential = Support::generateCredential();
expect((bool)preg_match('/^[A-Za-z0-9_-]{43}$/D', $credential), 'credential format is invalid');
expect(
    hash_equals(Support::credentialHash($credential), hash('sha256', $credential, true)),
    'credential hashing failed'
);

$params = Support::validateOperation('robber.scan', ['path' => 'C:\\Program Files']);
expect($params['image_type'] === 'any' && $params['best_dll_count'] === 2, 'defaults failed');
expectInvalid(
    static fn() => Support::validateOperation('shell.exec', ['command' => 'whoami']),
    'unknown operation was accepted'
);
expectInvalid(
    static fn() => Support::validateOperation('robber.scan', [
        'path' => 'C:\\Program Files', 'command' => 'whoami',
    ]),
    'unknown scan parameter was accepted'
);
expectInvalid(
    static fn() => Support::validateOperation('robber.scan', ['path' => '\\\\server\\share']),
    'UNC path was accepted'
);

echo "Support tests passed\n";
