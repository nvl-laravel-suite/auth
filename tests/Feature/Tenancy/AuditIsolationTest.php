<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Nvl\Auth\Actions\Audit\ListAuthAuditsAction;
use Nvl\Auth\Actions\Audit\ShowAuthAuditAction;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\TenantAwareAuthActivityBridge;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Services\CentralIdentityAuditRecorder;
use Nvl\Auth\Services\DisabledTenantAwareAuthActivityBridge;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Enums\TenantContextMode;

it('persists audit ownership when the event is recorded', function (): void {
    $scenario = new AuthTenancyScenario;
    $scenario->run($scenario->a(), fn () => app(AuthAuditRecorder::class)->record('membership.test'));
    $scenario->run($scenario->b(), fn () => app(AuthAuditRecorder::class)->record('membership.test'));
    $rows = AuthAudit::query()->where('action', 'membership.test')->orderBy('tenant_id')->get();

    expect($rows->pluck('tenant_id')->all())->toBe([$scenario->a()->value, $scenario->b()->value]);
});

it('isolates tenant audit reads and keeps central identity facts platform-owned', function (): void {
    $scenario = new AuthTenancyScenario;
    $actor = $this->user();
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($actor), true);
    $scenario->member($scenario->b(), SubjectReference::fromAuthenticatable($actor), true);
    $foreign = $scenario->run($scenario->b(), fn () => app(AuthAuditRecorder::class)->record('membership.foreign'));
    app(CentralIdentityAuditRecorder::class)->record(
        AuthIdentityOperation::Login,
        'authentication.succeeded',
        actor: $actor,
    );

    $rows = $scenario->run($scenario->a(), fn () => app(ListAuthAuditsAction::class)->execute($actor));
    expect($rows)->toHaveCount(0)
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->value('ownership_key'))->toBe('platform')
        ->and(fn () => $scenario->run(
            $scenario->a(),
            fn () => app(ShowAuthAuditAction::class)->execute($actor, $foreign),
        ))->toThrow(ModelNotFoundException::class);
});

it('refuses an activity projection while its tenant-safe bridge is disabled', function (): void {
    config()->set('nvl-auth.tenancy.activity_bridge', 'disabled');
    app()->forgetInstance(TenantAwareAuthActivityBridge::class);

    expect(fn () => app(TenantAwareAuthActivityBridge::class)->record(
        'membership.test',
        new AuthEventContext(TenantContextMode::Tenant, (new AuthTenancyScenario)->a()),
        ['membership_id' => 'safe-scalar'],
    ))->toThrow(AuthException::class);

    expect(app(TenantAwareAuthActivityBridge::class))->toBeInstanceOf(DisabledTenantAwareAuthActivityBridge::class);
});
