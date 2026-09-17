<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyRegistrationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyRegistrationAction;
use Nvl\Auth\Adapters\Laravel\LaravelBrowserSession;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Data\Mutations\FinishPasskeyRegistrationData;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\TenantAuthenticationIntent;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\Tests\Fixtures\AuthTestTenantDirectory;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;
use Nvl\Auth\ValueObjects\PendingTenantAuthenticationIntent;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantDirectory;
use Nvl\Tenancy\Enums\TenantStatus;
use Nvl\Tenancy\ValueObjects\TenantId;

it('preserves a server flow binding across session identifier regeneration', function (): void {
    $request = Request::create('/');
    $request->setLaravelSession(app('session')->driver());
    $session = new LaravelBrowserSession($request);
    $binding = $session->authenticationFlowBinding('social:github');

    $session->regenerateIdentifier();

    expect($session->authenticationFlowBinding('social:github'))->toBe($binding)
        ->and($binding)->not->toBeEmpty();
});

it('bounds expires and rejects ambiguous pending tenant session state', function (): void {
    $request = Request::create('/');
    $request->setLaravelSession(app('session')->driver());
    $session = new LaravelBrowserSession($request);
    $subject = new SubjectReference('users', 'subject-1');
    $tenant = new TenantId((string) Str::uuid());
    $intent = static fn (string $suffix, TenantId $target, CarbonImmutable $expiresAt): PendingTenantAuthenticationIntent => new PendingTenantAuthenticationIntent(
        $subject,
        "nonce-{$suffix}",
        "binding-{$suffix}",
        TenantAuthenticationPurpose::MagicLink,
        'magic_link',
        true,
        $target,
        $expiresAt,
    );

    $session->storePendingTenantAuthenticationIntent($intent('expired', $tenant, CarbonImmutable::now()->subSecond()));
    expect($session->pendingTenantAuthenticationIntent($tenant, $subject))->toBeNull();

    $session->storePendingTenantAuthenticationIntent($intent('one', $tenant, CarbonImmutable::now()->addMinutes(5)));
    $session->storePendingTenantAuthenticationIntent($intent('two', $tenant, CarbonImmutable::now()->addMinutes(6)));
    expect(fn () => $session->pendingTenantAuthenticationIntent($tenant, $subject))
        ->toThrow(AuthException::class, 'More than one');

    $request->session()->forget('nvl-auth.pending-tenant-authentication-intents');
    for ($index = 0; $index < 9; $index++) {
        $session->storePendingTenantAuthenticationIntent($intent(
            (string) $index,
            new TenantId((string) Str::uuid()),
            CarbonImmutable::now()->addMinutes($index + 1),
        ));
    }
    expect($request->session()->get('nvl-auth.pending-tenant-authentication-intents'))->toHaveCount(8);
});

it('carries a subject-bound tenant intent through the real magic-link HTTP transport once', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $user = $this->user('magic-http@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($user));

    $this->withSession([])->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/magic-links', ['recipient' => $user->email])
        ->assertAccepted();
    /** @var AuthDeliveryRequested $delivery */
    $delivery = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];
    $challengeId = $delivery->request->payload['challenge_id'];
    $token = $delivery->request->payload['secret'];

    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/magic-links/consume', ['challengeId' => $challengeId, 'token' => $token])
        ->assertOk()
        ->assertJsonPath('code', 'magic_link_consumed');

    $this->assertAuthenticatedAs($user);
    expect(Challenge::query()->findOrFail($challengeId)->consumed_at)->not->toBeNull()
        ->and(TenantAuthenticationIntent::query()->sole()->consumed_at)->not->toBeNull()
        ->and(AuthAudit::query()->where('action', 'authentication.tenant_selected')->exists())->toBeTrue();
});

it('does not consume a tenant intent for a mismatched HTTP tenant and consumes it once for the correct tenant', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $user = $this->user('magic-mismatch@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($user));

    $this->withSession([])->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/magic-links', ['recipient' => $user->email])
        ->assertAccepted();
    /** @var AuthDeliveryRequested $delivery */
    $delivery = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];
    $challengeId = $delivery->request->payload['challenge_id'];

    $this->withHeader('X-Test-Tenant', $scenario->b()->value)->postJson('/api/v1/auth/magic-links/consume', [
        'challengeId' => $challengeId,
        'token' => $delivery->request->payload['secret'],
    ])->assertOk();

    $this->assertAuthenticatedAs($user);
    expect(Challenge::query()->findOrFail($challengeId)->consumed_at)->not->toBeNull()
        ->and(TenantAuthenticationIntent::query()->sole()->consumed_at)->toBeNull()
        ->and(AuthAudit::query()->where('action', 'authentication.tenant_selection_denied')->count())->toBe(1);

    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertOk()
        ->assertJsonPath('data.tenant_id', $scenario->a()->value);

    expect(TenantAuthenticationIntent::query()->sole()->consumed_at)->not->toBeNull()
        ->and(AuthAudit::query()->where('action', 'authentication.tenant_selected')->count())->toBe(1);

    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertGone()
        ->assertJsonPath('code', 'tenant_authentication_intent_unavailable');
});

it('keeps concurrent same-browser tenant flows independently retryable without client intent input', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $user = $this->user('magic-concurrent@example.test');
    $reference = SubjectReference::fromAuthenticatable($user);
    $scenario->member($scenario->a(), $reference);
    $scenario->member($scenario->b(), $reference);

    $this->withSession([])->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/magic-links', ['recipient' => $user->email])
        ->assertAccepted();
    $this->withHeader('X-Test-Tenant', $scenario->b()->value)
        ->postJson('/api/v1/auth/security-codes/authentication', [
            'recipient' => $user->email,
            'purpose' => 'passwordless_login',
        ])
        ->assertAccepted();
    $deliveries = Event::dispatched(AuthDeliveryRequested::class);

    $this->withHeader('X-Test-Tenant', $scenario->b()->value)->postJson('/api/v1/auth/magic-links/consume', [
        'challengeId' => $deliveries[0][0]->request->payload['challenge_id'],
        'token' => $deliveries[0][0]->request->payload['secret'],
    ])->assertOk();
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)->postJson('/api/v1/auth/security-codes/authentication/verify', [
        'recipient' => $user->email,
        'purpose' => 'passwordless_login',
        'code' => $deliveries[1][0]->request->payload['secret'],
    ])->assertOk();

    expect(TenantAuthenticationIntent::query()->whereNotNull('consumed_at')->count())->toBe(0);
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete', ['nonce' => 'client-controlled'])
        ->assertUnprocessable()
        ->assertJsonPath('code', 'tenant_authentication_intent_input_invalid');
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertOk();
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertGone();
    $this->withHeader('X-Test-Tenant', $scenario->b()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertOk();
    $this->withHeader('X-Test-Tenant', $scenario->b()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertGone();

    expect(TenantAuthenticationIntent::query()->whereNotNull('consumed_at')->count())->toBe(2)
        ->and(AuthAudit::query()->where('action', 'authentication.tenant_selected')->count())->toBe(2);
});

it('authenticates tenant retry through the configured non-default guard', function (): void {
    config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);
    config()->set('nvl-auth.guard', 'admin');
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $user = $this->user('magic-admin-guard@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($user));

    $this->withSession([])->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/magic-links', ['recipient' => $user->email])
        ->assertAccepted();
    /** @var AuthDeliveryRequested $delivery */
    $delivery = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];
    $this->withHeader('X-Test-Tenant', $scenario->b()->value)->postJson('/api/v1/auth/magic-links/consume', [
        'challengeId' => $delivery->request->payload['challenge_id'],
        'token' => $delivery->request->payload['secret'],
    ])->assertOk();

    expect(auth('admin')->check())->toBeTrue()
        ->and(auth('web')->check())->toBeFalse();
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertOk();
    expect(TenantAuthenticationIntent::query()->sole()->consumed_at)->not->toBeNull();
});

it('denies expired and suspended magic-link tenant intents without failing global login', function (string $condition): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $user = $this->user("magic-{$condition}@example.test");
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($user));

    $this->withSession([])->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/magic-links', ['recipient' => $user->email])
        ->assertAccepted();
    /** @var AuthDeliveryRequested $delivery */
    $delivery = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];

    if ($condition === 'expired') {
        TenantAuthenticationIntent::query()->update(['expires_at' => now()->subMinute()]);
    }
    if ($condition === 'suspended') {
        $directory = app(TenantDirectory::class);
        expect($directory)->toBeInstanceOf(AuthTestTenantDirectory::class);
        $directory->setStatus($scenario->a(), TenantStatus::Suspended);
    }
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)->postJson('/api/v1/auth/magic-links/consume', [
        'challengeId' => $delivery->request->payload['challenge_id'],
        'token' => $delivery->request->payload['secret'],
    ])->assertOk();

    $this->assertAuthenticatedAs($user);
    expect(AuthAudit::query()->where('action', 'authentication.tenant_selection_denied')->exists())->toBeTrue();
})->with(['expired', 'suspended']);

it('carries tenant intent through real security-code and passkey HTTP transports', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $user = $this->user('passwordless-http@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($user));

    $this->withSession([])->withHeader('X-Test-Tenant', $scenario->a()->value)->postJson('/api/v1/auth/security-codes/authentication', [
        'recipient' => $user->email,
        'purpose' => 'passwordless_login',
    ])->assertAccepted();
    /** @var AuthDeliveryRequested $codeDelivery */
    $codeDelivery = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];
    $this->withHeader('X-Test-Tenant', $scenario->b()->value)->postJson('/api/v1/auth/security-codes/authentication/verify', [
        'recipient' => $user->email,
        'purpose' => 'passwordless_login',
        'code' => $codeDelivery->request->payload['secret'],
    ])->assertOk()->assertJsonPath('code', 'security_code_authenticated');
    expect(TenantAuthenticationIntent::query()->whereNotNull('consumed_at')->count())->toBe(0);
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertOk();

    auth('web')->logout();
    $this->app->singleton(PasskeyCeremony::class, TestPasskeyCeremony::class);
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    app(FinishPasskeyRegistrationAction::class)->execute(
        $user,
        new FinishPasskeyRegistrationData($registration->ceremonyId, ['valid' => true]),
    );
    $authentication = $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/passkeys/authentication/options')
        ->assertOk();
    $this->withHeader('X-Test-Tenant', $scenario->b()->value)->postJson('/api/v1/auth/passkeys/authentication', [
        'ceremonyId' => $authentication->json('data.ceremony_id'),
        'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2],
    ])->assertOk()->assertJsonPath('data.subject.id', (string) $user->getKey());

    $this->assertAuthenticatedAs($user);
    expect(TenantAuthenticationIntent::query()->whereNotNull('consumed_at')->count())->toBe(1);
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/tenant-intents/complete')
        ->assertOk();
    expect(TenantAuthenticationIntent::query()->whereNotNull('consumed_at')->count())->toBe(2)
        ->and(AuthAudit::query()->where('action', 'authentication.tenant_selected')->count())->toBe(2);
});
