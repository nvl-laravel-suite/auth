<?php

declare(strict_types=1);

use Nvl\Auth\Services\AuthUserReader;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

it('does not let a tenant owner delete or enumerate a global principal', function (): void {
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('owner-boundary@example.test');
    $target = $this->user('target-boundary@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);

    expect(fn () => $scenario->run($scenario->a(), fn () => app(AuthUsers::class)->delete($owner, $target)))
        ->toThrow(OwnershipViolation::class)
        ->and(fn () => $scenario->run($scenario->a(), fn () => app(AuthUserReader::class)->find($owner, $target)))
        ->toThrow(OwnershipViolation::class);
    expect($target->fresh())->not->toBeNull();
});

it('permits global principal administration only in explicit platform context', function (): void {
    $scenario = new AuthOwnerScenario;
    $actor = $this->user('platform-admin@example.test');
    $target = $this->user('platform-target@example.test');

    $deleted = $scenario->platform(fn () => app(AuthUsers::class)->delete($actor, $target));

    expect($deleted)->toBeTrue()->and(TestUser::query()->find($target->id))->toBeNull();
});
