<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Actions\ApiTokens\CreateApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\ListApiTokensAction;
use Nvl\Auth\Actions\ApiTokens\RevokeAllApiTokensAction;
use Nvl\Auth\Actions\ApiTokens\RotateApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\UpdateApiTokenAction;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Definitions\Tables\AuthTables;

it('manages tokens directly through sanctum without an auth projection', function (): void {
    config()->set('nvl-auth.features.api_tokens.enabled', true);
    config()->set('nvl-auth.features.api_tokens.settings.abilities', ['reports:read']);
    $user = $this->user();
    $hostToken = $user->createToken('host-owned', ['host:read']);
    $issued = app(CreateApiTokenAction::class)->execute(
        $user,
        new ApiTokenData('automation', ['reports:read']),
    );

    expect($issued->plainTextToken)->toContain('|')
        ->and(app(ListApiTokensAction::class)->execute($user))->toHaveCount(1)
        ->and($issued->token->name)->toBe('automation')
        ->and($issued->token->abilities)->toBe(['reports:read'])
        ->and(Schema::hasTable(AuthTables::PersonalAccessTokens))->toBeTrue()
        ->and(Schema::hasTable('personal_access_tokens'))->toBeFalse()
        ->and(Schema::hasTable('auth_api_tokens'))->toBeFalse();

    $updated = app(UpdateApiTokenAction::class)->execute(
        $user,
        $issued->token->id,
        new ApiTokenData('renamed', ['reports:read']),
    );
    $rotated = app(RotateApiTokenAction::class)->execute(
        $user,
        $updated->id,
        new ApiTokenData('rotated', ['reports:read']),
    );

    expect($updated->name)->toBe('renamed')
        ->and($rotated->token->id)->not->toBe($updated->id)
        ->and(app(RevokeAllApiTokensAction::class)->execute($user))->toBe(1)
        ->and(app(ListApiTokensAction::class)->execute($user))->toBeEmpty()
        ->and($user->tokens()->whereKey($hostToken->accessToken->getKey())->exists())->toBeTrue()
        ->and($user->tokens()->where('name', 'host-owned')->exists())->toBeTrue();
});
