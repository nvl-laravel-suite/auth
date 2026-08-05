<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;

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
