<?php

declare(strict_types=1);

use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Services\PrincipalAdoptionManifest;

/**
 * @return array<string, mixed>
 */
function validPrincipalAdoptionManifest(): array
{
    $columns = [];

    foreach (PrincipalAttribute::cases() as $attribute) {
        $columns[$attribute->value] = $attribute->value;
    }

    return [
        'version' => 1,
        'connection' => ' legacy ',
        'staging' => [[
            'source_table' => 'legacy_users',
            'staging_table' => 'legacy_users_staging',
        ]],
        'principals' => [
            'table' => 'legacy_users_staging',
            'expected_count' => 2,
            'columns' => $columns,
            'extension_columns' => ['domain_reference' => 'legacy_reference'],
        ],
        'password_reset_tokens' => [
            'table' => 'legacy_password_resets',
            'expected_count' => 1,
            'columns' => [
                'email' => 'email',
                'token' => 'token',
                'created_at' => null,
            ],
        ],
        'foreign_keys' => [[
            'table' => 'orders',
            'column' => 'user_id',
            'name' => 'orders_user_id_foreign',
            'on_delete' => 'cascade',
        ]],
        'drop_sources' => true,
    ];
}

it('normalizes every supported principal adoption section for host consumers', function (): void {
    $plan = app(PrincipalAdoptionManifest::class)->normalize(validPrincipalAdoptionManifest());

    expect($plan->connection)->toBe('legacy')
        ->and($plan->stages)->toHaveCount(1)
        ->and($plan->principals->table)->toBe('legacy_users_staging')
        ->and($plan->principals->extensionColumns)->toBe([
            'domain_reference' => 'legacy_reference',
        ])
        ->and($plan->passwordResetTokens?->columns['created_at'])->toBeNull()
        ->and($plan->foreignKeys)->toHaveCount(1)
        ->and($plan->foreignKeys[0]->onDelete)->toBe('cascade')
        ->and($plan->dropSources)->toBeTrue();
});

it('rejects malformed principal adoption manifests before any database mutation', function (): void {
    $cases = [
        'unknown manifest key' => [
            static function (array $manifest): array {
                $manifest['unexpected'] = true;

                return $manifest;
            },
            'manifest contains unknown key',
        ],
        'version' => [
            static function (array $manifest): array {
                $manifest['version'] = 2;

                return $manifest;
            },
            'version must be 1',
        ],
        'connection' => [
            static function (array $manifest): array {
                $manifest['connection'] = '';

                return $manifest;
            },
            'connection must be a name or null',
        ],
        'principal object' => [
            static function (array $manifest): array {
                $manifest['principals'] = [];

                return $manifest;
            },
            'principals must be an object',
        ],
        'unknown principal key' => [
            static function (array $manifest): array {
                $manifest['principals']['unexpected'] = true;

                return $manifest;
            },
            'principals contains unknown key',
        ],
        'column object' => [
            static function (array $manifest): array {
                $manifest['principals']['columns'] = [];

                return $manifest;
            },
            'columns must be an object',
        ],
        'missing canonical column' => [
            static function (array $manifest): array {
                unset($manifest['principals']['columns']['timezone']);

                return $manifest;
            },
            'must explicitly map [timezone]',
        ],
        'invalid canonical column' => [
            static function (array $manifest): array {
                $manifest['principals']['columns']['timezone'] = 42;

                return $manifest;
            },
            'must be a source column or null',
        ],
        'null required column' => [
            static function (array $manifest): array {
                $manifest['principals']['columns']['email'] = null;

                return $manifest;
            },
            'column [email] cannot be null',
        ],
        'invalid principal identifier' => [
            static function (array $manifest): array {
                $manifest['principals']['table'] = 'invalid-table';

                return $manifest;
            },
            'valid database identifier',
        ],
        'negative principal count' => [
            static function (array $manifest): array {
                $manifest['principals']['expected_count'] = -1;

                return $manifest;
            },
            'expected_count must be non-negative',
        ],
        'extension object' => [
            static function (array $manifest): array {
                $manifest['principals']['extension_columns'] = 'invalid';

                return $manifest;
            },
            'extension_columns must be an object',
        ],
        'extension entry' => [
            static function (array $manifest): array {
                $manifest['principals']['extension_columns'] = [0 => 'legacy_reference'];

                return $manifest;
            },
            'contains an invalid entry',
        ],
        'password reset object' => [
            static function (array $manifest): array {
                $manifest['password_reset_tokens'] = [];

                return $manifest;
            },
            'password_reset_tokens must be an object',
        ],
        'unknown password reset key' => [
            static function (array $manifest): array {
                $manifest['password_reset_tokens']['unexpected'] = true;

                return $manifest;
            },
            'password_reset_tokens contains unknown key',
        ],
        'password reset column object' => [
            static function (array $manifest): array {
                $manifest['password_reset_tokens']['columns'] = [];

                return $manifest;
            },
            'password-reset columns must be an object',
        ],
        'unknown password reset column' => [
            static function (array $manifest): array {
                $manifest['password_reset_tokens']['columns']['unexpected'] = 'unexpected';

                return $manifest;
            },
            'password-reset columns contains unknown key',
        ],
        'missing password reset column' => [
            static function (array $manifest): array {
                unset($manifest['password_reset_tokens']['columns']['token']);

                return $manifest;
            },
            'column [token] is required',
        ],
        'invalid password reset timestamp' => [
            static function (array $manifest): array {
                $manifest['password_reset_tokens']['columns']['created_at'] = 42;

                return $manifest;
            },
            'created_at must be a source column or null',
        ],
        'staging list' => [
            static function (array $manifest): array {
                $manifest['staging'] = ['source_table' => 'legacy_users'];

                return $manifest;
            },
            'staging must be a JSON list',
        ],
        'staging entry' => [
            static function (array $manifest): array {
                $manifest['staging'] = ['invalid'];

                return $manifest;
            },
            'staging entry must be an object',
        ],
        'unknown staging key' => [
            static function (array $manifest): array {
                $manifest['staging'][0]['unexpected'] = true;

                return $manifest;
            },
            'staging entry contains unknown key',
        ],
        'duplicate staging table' => [
            static function (array $manifest): array {
                $manifest['staging'][0]['staging_table'] = 'legacy_users';

                return $manifest;
            },
            'table names must be distinct',
        ],
        'foreign key list' => [
            static function (array $manifest): array {
                $manifest['foreign_keys'] = ['table' => 'orders'];

                return $manifest;
            },
            'foreign_keys must be a JSON list',
        ],
        'foreign key entry' => [
            static function (array $manifest): array {
                $manifest['foreign_keys'] = ['invalid'];

                return $manifest;
            },
            'foreign key must be an object',
        ],
        'unknown foreign key' => [
            static function (array $manifest): array {
                $manifest['foreign_keys'][0]['unexpected'] = true;

                return $manifest;
            },
            'foreign key contains unknown key',
        ],
        'foreign key delete policy' => [
            static function (array $manifest): array {
                $manifest['foreign_keys'][0]['on_delete'] = 'set-default';

                return $manifest;
            },
            'on_delete is invalid',
        ],
    ];

    foreach ($cases as $label => [$mutate, $message]) {
        expect(
            static fn () => app(PrincipalAdoptionManifest::class)->normalize(
                $mutate(validPrincipalAdoptionManifest()),
            ),
            $label,
        )->toThrow(InvalidArgumentException::class, $message);
    }
});

it('enforces a positive bounded principal adoption record limit', function (): void {
    config()->set('nvl-auth.adoption.maximum_records', 0);

    expect(static fn () => app(PrincipalAdoptionManifest::class)->normalize(validPrincipalAdoptionManifest()))
        ->toThrow(InvalidArgumentException::class, 'must be a positive integer');

    config()->set('nvl-auth.adoption.maximum_records', 2);

    expect(static fn () => app(PrincipalAdoptionManifest::class)->normalize(validPrincipalAdoptionManifest()))
        ->toThrow(InvalidArgumentException::class, 'exceeds the configured 2 record limit');
});
