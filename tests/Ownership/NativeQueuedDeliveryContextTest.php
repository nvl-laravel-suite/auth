<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;

it('captures queued delivery tenancy before a later context change', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('owner@example.test');
    $reference = SubjectReference::fromAuthenticatable($owner);
    $scenario->member($scenario->a(), $reference, true);
    $scenario->member($scenario->b(), $reference, true);

    $scenario->run($scenario->a(), fn () => app(AuthInvitations::class)->create(
        ['recipient' => 'invited@example.test'],
        $owner,
    ));
    $scenario->run($scenario->b(), static fn (): bool => true);
    /** @var AuthDeliveryRequested $event */
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    /** @var AuthDeliveryRequested $restored */
    $restored = unserialize(serialize($event), ['allowed_classes' => true]);

    expect($restored->ownershipJobEnvelope()->context()->mode)->toBe(OwnershipContextMode::Owner)
        ->and($restored->ownershipJobEnvelope()->context()->owner?->scopeKey())->toBe($scenario->a()->scopeKey());
});
