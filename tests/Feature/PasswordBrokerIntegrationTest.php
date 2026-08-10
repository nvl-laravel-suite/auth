<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Actions\Passwords\RequestPasswordResetAction;
use Nvl\Auth\Actions\Passwords\ResetPasswordAction;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Data\Mutations\RequestPasswordResetData;
use Nvl\Auth\Data\Mutations\ResetPasswordData;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;

it('uses laravel password broker storage and emits delivery instead of notifications', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user();
    app(RequestPasswordResetAction::class)->execute(new RequestPasswordResetData($user->email));
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0] ?? null;

    expect($event)->toBeInstanceOf(AuthDeliveryRequested::class)
        ->and($event->request->payload['token'])->toBeString();

    app(ResetPasswordAction::class)->execute(
        new ResetPasswordData(
            $user->email,
            $event->request->payload['token'],
            'new-secure-password',
            'new-secure-password',
        )
    );

    expect(Hash::check('new-secure-password', $user->refresh()->password))->toBeTrue();
});

it('applies replaceable eligibility before reset delivery and credential mutation', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user('ineligible@example.test');
    app(RequestPasswordResetAction::class)->execute(new RequestPasswordResetData($user->email));
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0] ?? null;

    $this->app->instance(AuthenticationEligibility::class, new class implements AuthenticationEligibility
    {
        public function assertEligible(Authenticatable $subject, AuthenticationPurpose $purpose): void
        {
            throw new AuthException('host_subject_ineligible', 'Host policy rejected the subject.', 422);
        }
    });

    expect(fn () => app(ResetPasswordAction::class)->execute(new ResetPasswordData(
        $user->email,
        $event->request->payload['token'],
        'replacement-password',
        'replacement-password',
    )))->toThrow(AuthException::class, 'Host policy')
        ->and(Hash::check('correct-password', $user->refresh()->password))->toBeTrue();

    Event::fake([AuthDeliveryRequested::class]);
    app(RequestPasswordResetAction::class)->execute(new RequestPasswordResetData($user->email));
    Event::assertNotDispatched(AuthDeliveryRequested::class);
});
