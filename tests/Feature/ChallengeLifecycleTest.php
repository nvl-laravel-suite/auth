<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Middleware\EnsureAuthFeatureAvailable;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Middleware\RenderAuthExceptions;

it('issues hashed magic links and consumes them once', function (): void {
    config()->set('nvl-auth.features.magic_links.enabled', true);
    Event::fake([AuthDeliveryRequested::class]);
    $issued = app(AuthChallenges::class)->requestMagicLink(['recipient' => 'user@example.test']);

    expect($issued['challenge']->getRawOriginal('secret_hash'))->not->toBe($issued['secret'])
        ->and($issued['fallbackCode'])->toMatch('/^\d{6}$/')
        ->and($issued['challenge']->getRawOriginal('secondary_secret_hash'))->not->toBe($issued['fallbackCode'])
        ->and($issued['challenge']->toArray())->not->toHaveKeys(['secret_hash', 'secondary_secret_hash']);

    $consumed = app(AuthChallenges::class)->consumeMagicLink(['recipient' => '', 'token' => (string) $issued['fallbackCode'], 'challengeId' => $issued['challenge']->identifier()]);

    expect($consumed->consumed_at)->not->toBeNull()
        ->and(fn () => app(AuthChallenges::class)->consumeMagicLink(['recipient' => 'user@example.test', 'token' => $issued['secret']]))
        ->toThrow(AuthException::class);
    Event::assertDispatched(AuthDeliveryRequested::class);
});

it('binds public login links to resolved subjects and stays neutral for unknown identifiers', function (): void {
    config()->set('nvl-auth.features.magic_links.enabled', true);
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user();

    $issued = app(AuthChallenges::class)->requestMagicLinkAuthentication(['recipient' => $user->email], $this->authenticationContext());

    expect($issued)->not->toBeNull()
        ->and($issued['challenge']->subject_id)->toBe((string) $user->getKey())
        ->and(app(AuthChallenges::class)->requestMagicLinkAuthentication(['recipient' => 'unknown@example.test'], $this->authenticationContext()))->toBeNull();

    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
    Event::assertDispatched(
        AuthDeliveryRequested::class,
        static fn (AuthDeliveryRequested $event): bool => $event->request->subject?->type === $user->getMorphClass()
            && $event->request->subject->identifier === (string) $user->getKey(),
    );
    /** @var AuthDeliveryRequested $deliveryEvent */
    $deliveryEvent = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];
    /** @var AuthDeliveryRequested $restoredEvent */
    $restoredEvent = unserialize(serialize($deliveryEvent));

    expect($restoredEvent->request->subject?->identifier)->toBe((string) $user->getKey());
});

it('scopes numeric codes to their recipient and purpose', function (): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    $issued = app(AuthChallenges::class)->requestSecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login']);

    expect(fn () => app(AuthChallenges::class)->verifySecurityCode(['recipient' => 'other@example.test', 'purpose' => 'login', 'code' => $issued['secret']]))
        ->toThrow(AuthException::class);

    expect(app(AuthChallenges::class)->verifySecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login', 'code' => $issued['secret']])->consumed_at)
        ->not->toBeNull();
});

it('keeps generic security-code HTTP proof host-managed and unauthenticated when tenancy is disabled', function (): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    Event::fake([AuthDeliveryRequested::class]);
    app('router')->aliasMiddleware('nvl.auth.feature', EnsureAuthFeatureAvailable::class);
    Route::prefix('nvl/api/v1/auth')->name('nvl.auth.public.')
        ->middleware(RenderAuthExceptions::class)
        ->group(dirname(__DIR__).'/Fixtures/Consumer/routes/public/security_codes.php');

    $this->postJson('/nvl/api/v1/auth/security-codes', [
        'recipient' => 'host-managed@example.test',
        'purpose' => 'email_change',
    ])->assertAccepted();
    /** @var AuthDeliveryRequested $delivery */
    $delivery = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];

    $this->postJson('/nvl/api/v1/auth/security-codes/verify', [
        'recipient' => 'host-managed@example.test',
        'purpose' => 'email_change',
        'code' => $delivery->request->payload['secret'],
    ])->assertOk()->assertJsonPath('code', 'security_code_verified');

    $this->assertGuest();
    expect(Challenge::query()->sole()->subject_id)->toBeNull();
});

it('commits failed challenge attempts instead of rolling them back with the response', function (): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    $issued = app(AuthChallenges::class)->requestSecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login']);
    $wrongCode = $issued['secret'] === '000000' ? '111111' : '000000';

    expect(fn () => app(AuthChallenges::class)->verifySecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login', 'code' => $wrongCode]))
        ->toThrow(AuthException::class);

    expect(Challenge::query()->sole()->attempts)->toBe(1);
});

it('keeps one active challenge and caps committed attempts', function (): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    config()->set('nvl-auth.features.security_codes.settings.max_attempts', 2);
    $first = app(AuthChallenges::class)->requestSecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login']);
    $second = app(AuthChallenges::class)->requestSecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login']);
    $wrongCode = $second['secret'] === '000000' ? '111111' : '000000';

    expect($first['challenge']->refresh()->revoked_at)->not->toBeNull()
        ->and($first['challenge']->active_key)->toBeNull()
        ->and($second['challenge']->active_key)->not->toBeNull();

    foreach ([1, 2, 3] as $attempt) {
        expect(fn () => app(AuthChallenges::class)->verifySecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login', 'code' => $wrongCode]))
            ->toThrow(AuthException::class);
    }

    expect($second['challenge']->refresh()->attempts)->toBe(2)
        ->and($second['challenge']->active_key)->toBeNull()
        ->and(fn () => app(AuthChallenges::class)->verifySecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login', 'code' => $second['secret']]))
        ->toThrow(AuthException::class);
});

it('redraws a code that collides with a retained challenge for the same recipient', function (bool $magicLink): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    config()->set('nvl-auth.features.magic_links.enabled', true);
    $column = $magicLink ? 'secondary_secret_hash' : 'secret_hash';
    $collidedHash = null;
    Challenge::creating(function (Challenge $challenge) use (&$collidedHash, $column): void {
        if ($collidedHash === null) {
            $collidedHash = $challenge->getAttribute($column);
            Challenge::factory()->create([$column => $collidedHash, 'revoked_at' => now()]);
        }
    });
    $challenges = app(AuthChallenges::class);
    $issued = $magicLink
        ? $challenges->requestMagicLink(['recipient' => 'user@example.test'])
        : $challenges->requestSecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login']);

    expect($collidedHash)->toBeString();

    $consumed = $magicLink
        ? $challenges->consumeMagicLink(['recipient' => 'user@example.test', 'token' => (string) $issued['fallbackCode']])
        : $challenges->verifySecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login', 'code' => $issued['secret']]);
    expect($consumed->consumed_at)->not->toBeNull();
})->with(['security code' => false, 'magic-link fallback code' => true]);

it('reports a conflict instead of a database error when every redraw collides', function (): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    $colliding = false;
    Challenge::creating(function (Challenge $challenge) use (&$colliding): void {
        if (! $colliding) {
            $colliding = true;
            Challenge::factory()->create(['secret_hash' => $challenge->secret_hash, 'revoked_at' => now()]);
            $colliding = false;
        }
    });

    expect(fn () => app(AuthChallenges::class)->requestSecurityCode(['recipient' => 'user@example.test', 'purpose' => 'login']))
        ->toThrow(fn (AuthException $exception) => expect($exception->errorCode)->toBe('challenge_issue_conflict'));
});
