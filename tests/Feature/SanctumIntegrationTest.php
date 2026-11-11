<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Services\AuthTokens;

it('manages tokens directly through sanctum without an auth projection', function (): void {
    config()->set('nvl-auth.features.api_tokens.enabled', true);
    config()->set('nvl-auth.features.api_tokens.settings.abilities', ['reports:read']);
    $user = $this->user();
    $hostToken = $user->createToken('host-owned', ['host:read']);
    $issued = app(AuthTokens::class)->create(
        $user,
        ['name' => 'automation', 'abilities' => ['reports:read']],
    );

    expect($issued->plainTextToken)->toContain('|')
        ->and(app(AuthTokens::class)->all($user))->toHaveCount(1)
        ->and($issued->token['name'])->toBe('automation')
        ->and($issued->token['abilities'])->toBe(['reports:read'])
        ->and(Schema::hasTable(AuthTables::PersonalAccessTokens))->toBeTrue()
        ->and(Schema::hasTable('personal_access_tokens'))->toBeFalse()
        ->and(Schema::hasTable('auth_api_tokens'))->toBeFalse();

    $updated = app(AuthTokens::class)->update(
        $user,
        $issued->token['id'],
        ['name' => 'renamed', 'abilities' => ['reports:read']],
    );
    $rotated = app(AuthTokens::class)->rotate(
        $user,
        $updated['id'],
        ['name' => 'rotated', 'abilities' => ['reports:read']],
    );

    expect($updated['name'])->toBe('renamed')
        ->and($rotated->token['id'])->not->toBe($updated['id'])
        ->and(app(AuthTokens::class)->revokeAll($user))->toBe(1)
        ->and(app(AuthTokens::class)->all($user))->toBeEmpty()
        ->and($user->tokens()->whereKey($hostToken->accessToken->getKey())->exists())->toBeTrue()
        ->and($user->tokens()->where('name', 'host-owned')->exists())->toBeTrue();
});

it('matches the token namespace exactly when it contains a LIKE wildcard character', function (): void {
    config()->set('nvl-auth.features.api_tokens.enabled', true);
    config()->set('nvl-auth.features.api_tokens.settings.abilities', ['reports:read']);
    config()->set('nvl-auth.features.api_tokens.settings.namespace', 'acme_api');
    $user = $this->user();
    $user->createToken('acme-api:host-owned', ['host:read']);
    app(AuthTokens::class)->create($user, ['name' => 'automation', 'abilities' => ['reports:read']]);

    expect(array_column(app(AuthTokens::class)->all($user), 'name'))->toBe(['automation'])
        ->and(app(AuthTokens::class)->revokeAll($user))->toBe(1)
        ->and($user->tokens()->pluck('name')->all())->toBe(['acme-api:host-owned']);
});

it('matches the token namespace case-sensitively on every database collation', function (): void {
    config()->set('nvl-auth.features.api_tokens.enabled', true);
    config()->set('nvl-auth.features.api_tokens.settings.abilities', ['reports:read']);
    config()->set('nvl-auth.features.api_tokens.settings.namespace', 'acme');
    $user = $this->user();
    $host = $user->createToken('ACME:host-owned', ['host:read'])->accessToken;
    app(AuthTokens::class)->create($user, ['name' => 'automation', 'abilities' => ['reports:read']]);

    expect(array_column(app(AuthTokens::class)->all($user), 'name'))->toBe(['automation'])
        ->and(app(AuthTokens::class)->revoke($user, (string) $host->getKey()))->toBeFalse()
        ->and(app(AuthTokens::class)->revokeAll($user))->toBe(1)
        ->and($user->tokens()->pluck('name')->all())->toBe(['ACME:host-owned']);
});
