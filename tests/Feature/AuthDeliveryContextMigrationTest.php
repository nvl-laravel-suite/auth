<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthSchemaMigration;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Services\AuthSchemaManager;

it('upgrades the v1.0.1 schema without changing existing delivery rows', function (): void {
    resetAuthDeliveryFeatureSchema(false);
    $invitationId = (string) Str::uuid();
    $challengeId = (string) Str::uuid();
    $invitation = [
        'id' => $invitationId,
        'token_hash' => hash('sha256', 'invitation-token'),
        'recipient' => 'existing@example.test',
        'recipient_hash' => hash('sha256', 'existing@example.test'),
        'expires_at' => now()->addHour()->toDateTimeString(),
    ];
    $challenge = [
        'id' => $challengeId,
        'type' => 'magic_link',
        'purpose' => 'login',
        'secret_hash' => hash('sha256', 'challenge-secret'),
        'expires_at' => now()->addHour()->toDateTimeString(),
    ];

    DB::table(AuthTables::Invitations)->insert($invitation);
    DB::table(AuthTables::Challenges)->insert($challenge);
    $invitationBefore = (array) DB::table(AuthTables::Invitations)
        ->where('id', $invitationId)
        ->first();
    $challengeBefore = (array) DB::table(AuthTables::Challenges)
        ->where('id', $challengeId)
        ->first();

    try {
        authDeliveryCorrectiveMigration()->up();

        expect(Schema::hasColumn(AuthTables::Invitations, 'context_hash'))->toBeTrue()
            ->and(Schema::hasColumn(AuthTables::Challenges, 'secondary_secret_hash'))->toBeTrue()
            ->and(DB::table(AuthTables::Invitations)->where('id', $invitationId)->value('context_hash'))->toBeNull()
            ->and(DB::table(AuthTables::Challenges)->where('id', $challengeId)->value('secondary_secret_hash'))->toBeNull()
            ->and((array) DB::table(AuthTables::Invitations)->where('id', $invitationId)->first(array_keys($invitationBefore)))->toBe($invitationBefore)
            ->and((array) DB::table(AuthTables::Challenges)->where('id', $challengeId)->first(array_keys($challengeBefore)))->toBe($challengeBefore);
    } finally {
        resetAuthDeliveryFeatureSchema();
    }
});

it('accepts the v1.0.2 fresh schema and remains idempotent', function (): void {
    resetAuthDeliveryFeatureSchema(false);

    Schema::table(AuthTables::Invitations, function (Blueprint $table): void {
        $table->char('context_hash', 64)->nullable();
        $table->index('context_hash', 'nvl_auth_invitations_context_hash_index');
    });
    Schema::table(AuthTables::Challenges, function (Blueprint $table): void {
        $table->char('secondary_secret_hash', 64)->nullable();
        $table->unique('secondary_secret_hash', 'nvl_auth_challenges_secondary_secret_hash_unique');
    });

    try {
        authDeliveryCorrectiveMigration()->up();
        authDeliveryCorrectiveMigration()->up();

        expect(authDeliveryIndex(AuthTables::Invitations, 'nvl_auth_invitations_context_hash_index'))
            ->toMatchArray(['columns' => ['context_hash'], 'unique' => false])
            ->and(authDeliveryIndex(AuthTables::Challenges, 'nvl_auth_challenges_secondary_secret_hash_unique'))
            ->toMatchArray(['columns' => ['secondary_secret_hash'], 'unique' => true]);
    } finally {
        resetAuthDeliveryFeatureSchema();
    }
});

it('installs the complete v1.0.3 schema from a fresh baseline', function (): void {
    resetAuthDeliveryFeatureSchema(false);

    try {
        expect(Schema::hasColumn(AuthTables::Invitations, 'context_hash'))->toBeFalse()
            ->and(Schema::hasColumn(AuthTables::Challenges, 'secondary_secret_hash'))->toBeFalse();

        authDeliveryCorrectiveMigration()->up();

        expect(Schema::hasColumn(AuthTables::Invitations, 'context_hash'))->toBeTrue()
            ->and(Schema::hasColumn(AuthTables::Challenges, 'secondary_secret_hash'))->toBeTrue()
            ->and(authDeliveryIndex(AuthTables::Invitations, 'nvl_auth_invitations_context_hash_index'))
            ->toMatchArray(['columns' => ['context_hash'], 'unique' => false])
            ->and(authDeliveryIndex(AuthTables::Challenges, 'nvl_auth_challenges_secondary_secret_hash_unique'))
            ->toMatchArray(['columns' => ['secondary_secret_hash'], 'unique' => true]);
    } finally {
        resetAuthDeliveryFeatureSchema();
    }
});

it('does nothing when delivery feature tables do not exist', function (): void {
    authDeliveryBaselineMigration()->down();
    config()->set('nvl-auth.migrations.install_all', false);
    setAuthFeatures(false);

    try {
        authDeliveryBaselineMigration()->up();
        authDeliveryCorrectiveMigration()->up();

        expect(Schema::hasTable(AuthTables::Invitations))->toBeFalse()
            ->and(Schema::hasTable(AuthTables::Challenges))->toBeFalse();
    } finally {
        resetAuthDeliveryFeatureSchema();
    }
});

it('plans and repairs outdated delivery tables after later feature activation', function (): void {
    resetAuthDeliveryFeatureSchema(false);
    config()->set('nvl-auth.migrations.install_all', false);
    setAuthFeatures(false);
    config()->set('nvl-auth.features.invitations.enabled', true);
    config()->set('nvl-auth.features.magic_links.enabled', true);

    try {
        $schema = app(AuthSchemaManager::class);
        $plan = $schema->execute();
        $applied = $schema->execute(true);

        expect($plan['missing'])->toBe([])
            ->and($plan['outdated'])->toBe([
                AuthTables::Invitations => ['context_hash'],
                AuthTables::Challenges => ['secondary_secret_hash'],
            ])
            ->and($applied['outdated'])->toBe($plan['outdated'])
            ->and(Schema::hasColumn(AuthTables::Invitations, 'context_hash'))->toBeTrue()
            ->and(Schema::hasColumn(AuthTables::Challenges, 'secondary_secret_hash'))->toBeTrue();
    } finally {
        resetAuthDeliveryFeatureSchema();
    }
});

it('creates later-enabled delivery tables and applies their corrective schema', function (): void {
    authDeliveryBaselineMigration()->down();
    config()->set('nvl-auth.migrations.install_all', false);
    setAuthFeatures(false);
    authDeliveryBaselineMigration()->up();
    config()->set('nvl-auth.features.invitations.enabled', true);
    config()->set('nvl-auth.features.magic_links.enabled', true);

    try {
        $plan = app(AuthSchemaManager::class)->execute();
        $applied = app(AuthSchemaManager::class)->execute(true);

        expect($plan['missing'])->toBe([AuthTables::Invitations, AuthTables::Challenges])
            ->and($applied['created'])->toBe($plan['missing'])
            ->and(Schema::hasColumn(AuthTables::Invitations, 'context_hash'))->toBeTrue()
            ->and(Schema::hasColumn(AuthTables::Challenges, 'secondary_secret_hash'))->toBeTrue();
    } finally {
        resetAuthDeliveryFeatureSchema();
    }
});

it('refuses to repair outdated tables when migrations are host-owned', function (): void {
    resetAuthDeliveryFeatureSchema(false);
    config()->set('nvl-auth.migrations.enabled', false);

    try {
        $plan = app(AuthSchemaManager::class)->execute();

        expect($plan['outdated'])->toBe([
            AuthTables::Invitations => ['context_hash'],
            AuthTables::Challenges => ['secondary_secret_hash'],
        ])->and(fn (): array => app(AuthSchemaManager::class)->execute(true))
            ->toThrow(
                RuntimeException::class,
                'Auth schema apply is unavailable while migrations are host-owned.',
            );
    } finally {
        config()->set('nvl-auth.migrations.enabled', true);
        resetAuthDeliveryFeatureSchema();
    }
});

/**
 * Load the v1.0.1 feature-table migration.
 */
function authDeliveryBaselineMigration(): AuthSchemaMigration
{
    $migration = require dirname(__DIR__, 2).'/database/migrations/2026_08_02_000000_create_nvl_auth_tables.php';

    expect($migration)->toBeInstanceOf(Migration::class)
        ->and($migration)->toBeInstanceOf(AuthSchemaMigration::class);

    return $migration;
}

/**
 * Load the v1.0.3 delivery-context corrective migration.
 */
function authDeliveryCorrectiveMigration(): AuthSchemaMigration
{
    $migration = require dirname(__DIR__, 2).'/database/migrations/2026_08_12_000000_add_auth_delivery_context_columns.php';

    expect($migration)->toBeInstanceOf(Migration::class)
        ->and($migration)->toBeInstanceOf(AuthSchemaMigration::class);

    return $migration;
}

/**
 * Recreate the feature schema at its baseline or corrected version.
 */
function resetAuthDeliveryFeatureSchema(bool $corrected = true): void
{
    config()->set('nvl-auth.migrations.enabled', true);
    config()->set('nvl-auth.migrations.install_all', true);
    setAuthFeatures(true);
    authDeliveryBaselineMigration()->down();
    authDeliveryBaselineMigration()->up();

    if ($corrected) {
        authDeliveryCorrectiveMigration()->up();
    }
}

/**
 * Set every Auth feature switch to the same state.
 */
function setAuthFeatures(bool $enabled): void
{
    foreach (AuthFeature::cases() as $feature) {
        config()->set("nvl-auth.features.{$feature->value}.enabled", $enabled);
    }
}

/**
 * Return one named index from the current Auth schema.
 *
 * @return array<string, mixed>
 */
function authDeliveryIndex(string $table, string $name): array
{
    $index = collect(Schema::getIndexes($table))->firstWhere('name', $name);

    expect($index)->toBeArray();

    return $index;
}
