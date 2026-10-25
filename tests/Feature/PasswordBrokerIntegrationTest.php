<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthPasswords;

it('applies replaceable eligibility before reset delivery and credential mutation', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user('ineligible@example.test');
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0] ?? null;

    $this->app->instance(AuthenticationEligibility::class, new class implements AuthenticationEligibility
    {
        public function assertEligible(Authenticatable $subject, AuthenticationPurpose $purpose): void
        {
            throw new AuthException('host_subject_ineligible', 'Host policy rejected the subject.', 422);
        }
    });

    expect(fn () => app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']))->toThrow(AuthException::class, 'Host policy')
        ->and(Hash::check('correct-password', $user->refresh()->password))->toBeTrue();

    Event::fake([AuthDeliveryRequested::class]);
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    Event::assertNotDispatched(AuthDeliveryRequested::class);
});
