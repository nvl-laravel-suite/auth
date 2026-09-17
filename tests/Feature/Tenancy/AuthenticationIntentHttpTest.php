<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyRegistrationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyRegistrationAction;
use Nvl\Auth\Adapters\Laravel\LaravelBrowserSession;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Data\Mutations\FinishPasskeyRegistrationData;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\TenantAuthenticationIntent;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\Tests\Fixtures\AuthTestTenantDirectory;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantDirectory;
use Nvl\Tenancy\Enums\TenantStatus;

it('preserves a server flow binding across session identifier regeneration', function (): void {
    $request = Request::create('/');
    $request->setLaravelSession(app('session')->driver());
    $session = new LaravelBrowserSession($request);
    $binding = $session->authenticationFlowBinding('social:github');

    $session->regenerateIdentifier();

    expect($session->authenticationFlowBinding('social:github'))->toBe($binding)
        ->and($binding)->not->toBeEmpty();
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
    expect(TenantAuthenticationIntent::query()->sole()->consumed_at)->not->toBeNull()
        ->and(AuthAudit::query()->where('action', 'authentication.tenant_selected')->exists())->toBeTrue();

    Challenge::query()->whereKey($challengeId)->update(['consumed_at' => null]);
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson('/api/v1/auth/magic-links/consume', ['challengeId' => $challengeId, 'token' => $token])
        ->assertOk();
    expect(AuthAudit::query()->where('action', 'authentication.tenant_selection_denied')->exists())->toBeTrue();
});

it('denies mismatched expired and suspended magic-link tenant intents without failing global login', function (string $condition): void {
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
    $completionTenant = $condition === 'mismatch' ? $scenario->b() : $scenario->a();

    $this->withHeader('X-Test-Tenant', $completionTenant->value)->postJson('/api/v1/auth/magic-links/consume', [
        'challengeId' => $delivery->request->payload['challenge_id'],
        'token' => $delivery->request->payload['secret'],
    ])->assertOk();

    $this->assertAuthenticatedAs($user);
    expect(AuthAudit::query()->where('action', 'authentication.tenant_selection_denied')->exists())->toBeTrue();
})->with(['mismatch', 'expired', 'suspended']);

it('carries tenant intent through real security-code and passkey HTTP transports', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $scenario = new AuthTenancyScenario;
    $user = $this->user('passwordless-http@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($user));

    $this->withSession([])->withHeader('X-Test-Tenant', $scenario->a()->value)->postJson('/api/v1/auth/security-codes', [
        'recipient' => $user->email,
        'purpose' => 'login',
    ])->assertAccepted();
    /** @var AuthDeliveryRequested $codeDelivery */
    $codeDelivery = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)->postJson('/api/v1/auth/security-codes/verify', [
        'recipient' => $user->email,
        'purpose' => 'login',
        'code' => $codeDelivery->request->payload['secret'],
    ])->assertOk()->assertJsonPath('code', 'security_code_verified');

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
    $this->withHeader('X-Test-Tenant', $scenario->a()->value)->postJson('/api/v1/auth/passkeys/authentication', [
        'ceremonyId' => $authentication->json('data.ceremony_id'),
        'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2],
    ])->assertOk()->assertJsonPath('data.subject.id', (string) $user->getKey());

    $this->assertAuthenticatedAs($user);
    expect(TenantAuthenticationIntent::query()->whereNotNull('consumed_at')->count())->toBe(2)
        ->and(AuthAudit::query()->where('action', 'authentication.tenant_selected')->count())->toBe(2);
});
