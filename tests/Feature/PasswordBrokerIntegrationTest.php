<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Actions\Passwords\RequestPasswordResetAction;
use Nvl\Auth\Actions\Passwords\ResetPasswordAction;
use Nvl\Auth\Data\Mutations\RequestPasswordResetData;
use Nvl\Auth\Data\Mutations\ResetPasswordData;
use Nvl\Auth\Events\AuthDeliveryRequested;

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
