<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Nvl\Auth\Actions\AdoptPrincipalsAction;
use Nvl\Auth\Models\User;

/**
 * @return array<string, mixed>
 */
function principalAdoptionManifestForTest(
    string $principalTable,
    int $principalCount,
    ?string $passwordTable = null,
    int $passwordCount = 0,
): array {
    return [
        'version' => 1,
        'connection' => null,
        'staging' => [],
        'principals' => [
            'table' => $principalTable,
            'expected_count' => $principalCount,
            'columns' => [
                'id' => 'id',
                'name' => 'name',
                'email' => 'email',
                'email_verified_at' => 'email_verified_at',
                'password' => 'password',
                'active' => 'active',
                'locale' => 'locale',
                'timezone' => 'timezone',
                'profile' => 'profile_data',
                'preferences' => null,
                'last_login_at' => null,
                'last_login_ip' => 'last_login_ip',
                'locked_until' => null,
                'remember_token' => null,
                'created_at' => 'created_at',
                'updated_at' => 'updated_at',
                'deleted_at' => null,
            ],
            'extension_columns' => ['domain_reference' => 'domain_reference'],
        ],
        'password_reset_tokens' => $passwordTable === null ? null : [
            'table' => $passwordTable,
            'expected_count' => $passwordCount,
            'columns' => [
                'email' => 'email',
                'token' => 'token',
                'created_at' => 'created_at',
            ],
        ],
        'foreign_keys' => [],
        'drop_sources' => false,
    ];
}

it('dry runs and applies a reconciled principal, token, extension, and foreign-key adoption', function (): void {
    Schema::table('nvl_auth_users', function (Blueprint $table): void {
        $table->string('domain_reference')->nullable();
    });
    Schema::create('legacy_users', function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->string('name');
        $table->string('email');
        $table->timestamp('email_verified_at')->nullable();
        $table->string('password')->nullable();
        $table->boolean('active');
        $table->string('locale');
        $table->string('timezone');
        $table->json('profile_data')->nullable();
        $table->string('last_login_ip')->nullable();
        $table->string('domain_reference')->nullable();
        $table->timestamps();
    });
    Schema::create('legacy_password_reset_tokens', function (Blueprint $table): void {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    });
    Schema::create('principal_domain_records', function (Blueprint $table): void {
        $table->id();
        $table->uuid('user_id');
        $table->foreign('user_id', 'principal_domain_records_user_id_foreign')
            ->references('id')
            ->on('legacy_users')
            ->restrictOnDelete();
    });
    $id = (string) Str::uuid();
    $now = now();
    DB::table('legacy_users')->insert([
        'id' => $id,
        'name' => 'Legacy Principal',
        'email' => 'LEGACY@EXAMPLE.TEST',
        'email_verified_at' => $now,
        'password' => password_hash('SecurePassword123', PASSWORD_BCRYPT),
        'active' => true,
        'locale' => 'bg',
        'timezone' => 'Europe/Sofia',
        'profile_data' => json_encode(['phone' => '+359000000000'], JSON_THROW_ON_ERROR),
        'last_login_ip' => '127.0.0.1',
        'domain_reference' => 'legacy-67',
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    DB::table('legacy_password_reset_tokens')->insert([
        'email' => 'LEGACY@EXAMPLE.TEST',
        'token' => 'legacy-token-hash',
        'created_at' => $now,
    ]);
    DB::table('principal_domain_records')->insert(['user_id' => $id]);
    $manifest = principalAdoptionManifestForTest('legacy_users', 1, 'legacy_password_reset_tokens', 1);
    $manifest['foreign_keys'] = [[
        'table' => 'principal_domain_records',
        'column' => 'user_id',
        'name' => 'principal_domain_records_user_id_foreign',
        'on_delete' => 'restrict',
    ]];
    $manifest['drop_sources'] = true;
    $action = app(AdoptPrincipalsAction::class);

    $plan = $action->execute($manifest);
    $result = $action->execute($manifest, apply: true);
    $user = User::query()->findOrFail($id);
    $foreignKeys = Schema::getForeignKeys('principal_domain_records');

    expect($plan['mode'])->toBe('plan')
        ->and($plan['reconciliation']['principals']['source'])->toBe(1)
        ->and($result['reconciliation']['principals']['matched'])->toBe(1)
        ->and($result['reconciliation']['password_reset_tokens']['matched'])->toBe(1)
        ->and($user->email)->toBe('legacy@example.test')
        ->and($user->profile)->toBe(['phone' => '+359000000000'])
        ->and($user->last_login_ip)->toBe('127.0.0.1')
        ->and($user->getAttribute('domain_reference'))->toBe('legacy-67')
        ->and(DB::table('nvl_auth_password_reset_tokens')->where('email', 'legacy@example.test')->value('token'))->toBe('legacy-token-hash')
        ->and(Schema::hasTable('legacy_users'))->toBeFalse()
        ->and(Schema::hasTable('legacy_password_reset_tokens'))->toBeFalse()
        ->and(collect($foreignKeys)->contains(
            static fn (array $foreignKey): bool => ($foreignKey['foreign_table'] ?? null) === 'nvl_auth_users',
        ))->toBeTrue();
});

it('rejects duplicate or non-UUID principal identities before writing', function (): void {
    Schema::create('invalid_legacy_users', function (Blueprint $table): void {
        $table->string('id');
        $table->string('name');
        $table->string('email');
        $table->timestamp('email_verified_at')->nullable();
        $table->string('password')->nullable();
        $table->boolean('active');
        $table->string('locale');
        $table->string('timezone');
        $table->json('profile_data')->nullable();
        $table->string('last_login_ip')->nullable();
        $table->string('domain_reference')->nullable();
        $table->timestamps();
    });
    DB::table('invalid_legacy_users')->insert([
        'id' => '67',
        'name' => 'Invalid Principal',
        'email' => 'invalid@example.test',
        'active' => true,
        'locale' => 'en',
        'timezone' => 'UTC',
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    $manifest = principalAdoptionManifestForTest('invalid_legacy_users', 1);
    $manifest['principals']['extension_columns'] = [];

    expect(fn () => app(AdoptPrincipalsAction::class)->execute($manifest))
        ->toThrow(InvalidArgumentException::class, 'invalid or duplicated')
        ->and(User::query()->where('email', 'invalid@example.test')->exists())->toBeFalse();
});

it('plans and applies pre-migration principal table staging', function (): void {
    Schema::create('staged_users_source', function (Blueprint $table): void {
        $table->uuid('id')->primary();
    });
    Schema::create('staged_domain_records', function (Blueprint $table): void {
        $table->id();
        $table->uuid('user_id')->nullable();
        $table->foreign('user_id', 'staged_domain_records_principal_foreign')
            ->references('id')
            ->on('staged_users_source')
            ->nullOnDelete();
    });
    $manifest = principalAdoptionManifestForTest('staged_users_target', 0);
    $manifest['staging'] = [[
        'source_table' => 'staged_users_source',
        'staging_table' => 'staged_users_target',
    ]];
    $manifest['foreign_keys'] = [[
        'table' => 'staged_domain_records',
        'column' => 'user_id',
        'name' => 'staged_domain_records_principal_foreign',
        'on_delete' => 'null',
    ]];
    $action = app(AdoptPrincipalsAction::class);

    $plan = $action->execute($manifest, stage: true);
    $applied = $action->execute($manifest, stage: true, apply: true);

    expect($plan['foreign_keys_detected'])->toBe(['staged_domain_records_principal_foreign'])
        ->and($applied['foreign_keys_detached'])->toBe(['staged_domain_records_principal_foreign'])
        ->and(Schema::hasTable('staged_users_source'))->toBeFalse()
        ->and(Schema::hasTable('staged_users_target'))->toBeTrue()
        ->and(Schema::getForeignKeys('staged_domain_records'))->toBe([]);
});

it('registers the dry-run principal adoption command', function (): void {
    expect(collect(Artisan::all())->has('nvl:auth:adopt-principals'))->toBeTrue();
});
