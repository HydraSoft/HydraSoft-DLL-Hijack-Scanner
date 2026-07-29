<?php
declare(strict_types=1);

namespace RobberRemote;

use InvalidArgumentException;

final class Support
{
    public const ALLOWED_OPERATIONS = ['robber.scan'];

    public static function normalizeBootstrapToken(string $token): string
    {
        $token = strtolower(trim($token));
        if (str_starts_with($token, '0x')) {
            $token = substr($token, 2);
        }
        if (!preg_match('/^[0-9a-f]{32}$/D', $token)) {
            throw new InvalidArgumentException('bootstrap_token must contain exactly 16 bytes of hex');
        }
        return $token;
    }

    public static function credentialHash(string $credential): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $credential)) {
            throw new InvalidArgumentException('Invalid agent credential');
        }
        return hash('sha256', $credential, true);
    }

    public static function generateCredential(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public static function bearerToken(array $server): ?string
    {
        $header = $server['HTTP_AUTHORIZATION'] ?? $server['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        return preg_match('/^Bearer\s+(\S+)$/i', $header, $match) ? $match[1] : null;
    }

    public static function validateOperation(string $operation, array $params): array
    {
        if (!in_array($operation, self::ALLOWED_OPERATIONS, true)) {
            throw new InvalidArgumentException('Operation is not allow-listed');
        }

        if ($operation === 'robber.scan') {
            $allowed = [
                'path', 'image_type', 'sign', 'rate', 'write_perm',
                'best_dll_count', 'best_exe_size', 'good_dll_count', 'good_exe_size',
            ];
            foreach (array_keys($params) as $key) {
                if (!in_array($key, $allowed, true)) {
                    throw new InvalidArgumentException("Unknown robber.scan parameter: {$key}");
                }
            }

            $path = $params['path'] ?? '';
            if (!is_string($path) || $path === '' || strlen($path) > 512 || str_starts_with($path, '\\\\')) {
                throw new InvalidArgumentException('path must be a local Windows path');
            }
            if (!in_array($params['image_type'] ?? 'any', ['any', 'x86', 'x64'], true)
                || !in_array($params['sign'] ?? 'any', ['any', 'signed'], true)
                || !in_array($params['rate'] ?? 'any', ['any', 'best', 'good', 'bad'], true)
                || !is_bool($params['write_perm'] ?? false)) {
                throw new InvalidArgumentException('Invalid robber.scan filter');
            }
            foreach ([
                'best_dll_count' => 2, 'best_exe_size' => 10240,
                'good_dll_count' => 5, 'good_exe_size' => 51200,
            ] as $key => $default) {
                $value = $params[$key] ?? $default;
                if (!is_int($value) || $value < 0 || $value > 1_000_000) {
                    throw new InvalidArgumentException("Invalid {$key}");
                }
                $params[$key] = $value;
            }
            $params += [
                'image_type' => 'any', 'sign' => 'any', 'rate' => 'any',
                'write_perm' => false,
            ];
        }
        return $params;
    }
}
