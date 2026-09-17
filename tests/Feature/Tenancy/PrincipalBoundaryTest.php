<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Users\DeleteUserAction;
use Nvl\Auth\Actions\Users\ShowUserAction;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;

it('does not let a tenant owner delete or enumerate a global principal', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner-boundary@example.test');
    $target = $this->user('target-boundary@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);

    expect(fn () => $scenario->run($scenario->a(), fn () => app(DeleteUserAction::class)->execute($owner, $target)))
        ->toThrow(TenantBoundaryViolation::class)
        ->and(fn () => $scenario->run($scenario->a(), fn () => app(ShowUserAction::class)->execute($owner, $target)))
        ->toThrow(TenantBoundaryViolation::class);
    expect($target->fresh())->not->toBeNull();
});

it('permits global principal administration only in explicit platform context', function (): void {
    $scenario = new AuthTenancyScenario;
    $actor = $this->user('platform-admin@example.test');
    $target = $this->user('platform-target@example.test');

    $deleted = $scenario->platform(fn () => app(DeleteUserAction::class)->execute($actor, $target));

    expect($deleted)->toBeTrue()->and(TestUser::query()->find($target->id))->toBeNull();
});
