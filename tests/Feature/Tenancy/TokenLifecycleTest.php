<?php

declare(strict_types=1);

use Nvl\Auth\Actions\ApiTokens\CreateApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\RevokeAllApiTokensAction;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('revokes only the active tenants tokens', function (): void {
    $scenario = new AuthTenancyScenario;
    $user = $this->user();
    $reference = SubjectReference::fromAuthenticatable($user);
    $scenario->member($scenario->a(), $reference);
    $scenario->member($scenario->b(), $reference);
    foreach ([$scenario->a(), $scenario->b()] as $tenant) {
        $scenario->run($tenant, fn () => app(CreateApiTokenAction::class)->execute(
            $user,
            new ApiTokenData('automation', ['profile:read']),
        ));
    }

    expect($scenario->run($scenario->a(), fn () => app(RevokeAllApiTokensAction::class)->execute($user)))->toBe(1)
        ->and($scenario->run($scenario->b(), fn () => app(ApiTokenManager::class)->list($user)))->toHaveCount(1);
});

it('keeps rotation bound to the active tenant and hides foreign tokens', function (): void {
    $scenario = new AuthTenancyScenario;
    $user = $this->user();
    $reference = SubjectReference::fromAuthenticatable($user);
    $scenario->member($scenario->a(), $reference);
    $scenario->member($scenario->b(), $reference);
    $issued = $scenario->run($scenario->a(), fn () => app(CreateApiTokenAction::class)->execute(
        $user,
        new ApiTokenData('automation', ['profile:read']),
    ));

    expect($scenario->run($scenario->b(), fn () => app(ApiTokenManager::class)->list($user)))->toBeEmpty()
        ->and($issued->token->tenantId)->toBe($scenario->a()->value)
        ->and(fn () => $scenario->run($scenario->b(), fn () => app(ApiTokenManager::class)->update(
            $user,
            $issued->token->id,
            new ApiTokenData('foreign', ['profile:read']),
        )))->toThrow(AuthException::class);

    $rotated = $scenario->run($scenario->a(), fn () => app(ApiTokenManager::class)->rotate(
        $user,
        $issued->token->id,
        new ApiTokenData('rotated', ['profile:read']),
    ));

    expect($rotated->token->tenantId)->toBe($scenario->a()->value)
        ->and($scenario->run($scenario->b(), fn () => app(ApiTokenManager::class)->revoke(
            $user,
            $rotated->token->id,
        )))->toBeFalse();
});
