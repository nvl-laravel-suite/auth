<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Enums\TenantContextMode;

it('captures queued delivery tenancy before a later context change', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner@example.test');
    $reference = SubjectReference::fromAuthenticatable($owner);
    $scenario->member($scenario->a(), $reference, true);
    $scenario->member($scenario->b(), $reference, true);

    $scenario->run($scenario->a(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('invited@example.test'),
        $owner,
    ));
    $scenario->run($scenario->b(), static fn (): bool => true);
    /** @var AuthDeliveryRequested $event */
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    /** @var AuthDeliveryRequested $restored */
    $restored = unserialize(serialize($event), ['allowed_classes' => true]);

    expect($restored->tenantJobEnvelope()->context->mode)->toBe(TenantContextMode::Tenant)
        ->and($restored->tenantJobEnvelope()->context->tenantId?->value)->toBe($scenario->a()->value)
        ->and($restored->request->tenant?->value)->toBe($scenario->a()->value);
});
