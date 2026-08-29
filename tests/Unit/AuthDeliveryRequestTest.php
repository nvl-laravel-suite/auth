<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Nvl\Auth\Data\Display\AuthSubjectReferenceData;
use Nvl\Auth\Data\Display\InvitationDeliveryData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\SubjectReference;

it('accepts bounded transport-neutral delivery data and redacts debug output', function (): void {
    $request = new AuthDeliveryRequest(
        messageId: 'message-1',
        feature: AuthFeature::MagicLinks,
        type: AuthMessageType::MagicLink,
        recipient: 'user@example.test',
        payload: ['token' => 'secret'],
        expiresAt: CarbonImmutable::now()->addMinute(),
        locale: 'en-US',
        metadata: ['tenant' => 'one'],
    );

    expect($request->__debugInfo())
        ->toMatchArray(['recipient' => '[REDACTED]', 'payload_keys' => ['token']])
        ->not->toContain('secret', 'user@example.test');
});

it('rejects expired or oversized delivery payloads', function (): void {
    expect(fn () => new AuthDeliveryRequest(
        messageId: 'message-1',
        feature: AuthFeature::MagicLinks,
        type: AuthMessageType::MagicLink,
        recipient: 'user@example.test',
        payload: [],
        expiresAt: CarbonImmutable::now()->subSecond(),
    ))->toThrow(InvalidArgumentException::class, 'future')
        ->and(fn () => new AuthDeliveryRequest(
            messageId: 'message-2',
            feature: AuthFeature::MagicLinks,
            type: AuthMessageType::MagicLink,
            recipient: 'user@example.test',
            payload: ['secret' => str_repeat('x', 32_769)],
            expiresAt: CarbonImmutable::now()->addMinute(),
        ))->toThrow(InvalidArgumentException::class, 'size');
});

it('rejects delivery message types outside their owning feature', function (): void {
    expect(fn () => new AuthDeliveryRequest(
        messageId: 'message-1',
        feature: AuthFeature::Authentication,
        type: AuthMessageType::EmailVerification,
        recipient: 'user@example.test',
        payload: [],
        expiresAt: CarbonImmutable::now()->addMinute(),
    ))->toThrow(InvalidArgumentException::class, 'incompatible');
});

it('carries queue-safe typed subject and invitation context without exposing values in debug output', function (): void {
    $expiresAt = CarbonImmutable::now()->addHour();
    $subject = new SubjectReference('user', 'subject-1');
    $invitation = new InvitationDeliveryData(
        id: 'invitation-1',
        type: 'registration',
        purpose: 'registration',
        recipient: 'invitee@example.test',
        inviter: AuthSubjectReferenceData::fromReference($subject),
        roles: ['member'],
        permissions: ['articles.read'],
        metadata: ['member_id' => 'member-1'],
        expiresAt: $expiresAt,
        resendCount: 0,
    );
    $request = new AuthDeliveryRequest(
        messageId: 'message-1',
        feature: AuthFeature::Invitations,
        type: AuthMessageType::Invitation,
        recipient: 'invitee@example.test',
        payload: ['token' => 'delivery-secret'],
        expiresAt: $expiresAt,
        subject: $subject,
        invitation: $invitation,
    );

    /** @var AuthDeliveryRequest $restored */
    $restored = unserialize(serialize($request));

    expect($restored->subject?->identifier)->toBe('subject-1')
        ->and($restored->invitation?->id)->toBe('invitation-1')
        ->and($restored->invitation?->metadata)->toBe(['member_id' => 'member-1'])
        ->and($request->__debugInfo())->toMatchArray([
            'subject_type' => 'user',
            'has_invitation' => true,
        ])->not->toContain(
            'subject-1',
            'invitation-1',
            'member-1',
            'delivery-secret',
            'invitee@example.test',
        );
});

it('rejects invitation context on unrelated delivery features', function (): void {
    $expiresAt = CarbonImmutable::now()->addHour();

    expect(fn () => new AuthDeliveryRequest(
        messageId: 'message-1',
        feature: AuthFeature::MagicLinks,
        type: AuthMessageType::MagicLink,
        recipient: 'user@example.test',
        payload: [],
        expiresAt: $expiresAt,
        invitation: new InvitationDeliveryData(
            id: 'invitation-1',
            type: 'registration',
            purpose: 'registration',
            recipient: 'invitee@example.test',
            inviter: null,
            roles: [],
            permissions: [],
            metadata: [],
            expiresAt: $expiresAt,
            resendCount: 0,
        ),
    ))->toThrow(InvalidArgumentException::class, 'Invitation delivery context');
});

it('restores optional context as null from delivery and acceptance events queued by an older release', function (): void {
    $expiresAt = CarbonImmutable::now()->addHour();
    $requestReflection = new ReflectionClass(AuthDeliveryRequest::class);
    /** @var AuthDeliveryRequest $legacyRequest */
    $legacyRequest = $requestReflection->newInstanceWithoutConstructor();

    foreach ([
        'messageId' => 'legacy-message',
        'feature' => AuthFeature::MagicLinks,
        'type' => AuthMessageType::MagicLink,
        'recipient' => 'legacy@example.test',
        'payload' => [],
        'expiresAt' => $expiresAt,
        'locale' => null,
        'metadata' => [],
    ] as $property => $value) {
        $requestReflection->getProperty($property)->setValue($legacyRequest, $value);
    }

    $acceptanceReflection = new ReflectionClass(InvitationAccepted::class);
    /** @var InvitationAccepted $legacyAcceptance */
    $legacyAcceptance = $acceptanceReflection->newInstanceWithoutConstructor();

    foreach ([
        'invitationId' => 'legacy-invitation',
        'type' => 'registration',
        'purpose' => 'registration',
        'subject' => new SubjectReference('user', 'subject-1'),
    ] as $property => $value) {
        $acceptanceReflection->getProperty($property)->setValue($legacyAcceptance, $value);
    }

    /** @var AuthDeliveryRequest $restoredRequest */
    $restoredRequest = unserialize(serialize($legacyRequest));
    /** @var InvitationAccepted $restoredAcceptance */
    $restoredAcceptance = unserialize(serialize($legacyAcceptance));

    expect($restoredRequest->subject)->toBeNull()
        ->and($restoredRequest->invitation)->toBeNull()
        ->and($restoredAcceptance->acceptedAt)->toBeNull();
});
