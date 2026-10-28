<?php

declare(strict_types=1);

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Filesystem\FilesystemServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Events\UserLoggedOut;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\AuthAuditReader;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\AuthClients;
use Nvl\Auth\Services\AuthEmailVerification;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthMaintenance;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthUserReader;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Ownership\Contracts\OwnerAccess;

it('publishes complete native operations with explicit typed arguments and returns', function (string $class): void {
    $reflection = new ReflectionClass($class);
    expect($reflection->isFinal())->toBeTrue()->and($reflection->isReadOnly())->toBeTrue()
        ->and($reflection->hasMethod('execute'))->toBeFalse();
    foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        if ($method->isConstructor()) {
            continue;
        }
        expect($method->hasReturnType())->toBeTrue();
        foreach ($method->getParameters() as $parameter) {
            expect($parameter->hasType())->toBeTrue();
            expect((string) $parameter->getType())->not->toContain('Data')->not->toContain('Illuminate\\Http\\Request');
        }
    }
})->with([
    [Authentication::class],
    [AuthenticationSessions::class],
    [AuthChallenges::class],
    [AuthPasswords::class],
    [AuthEmailVerification::class],
    [AuthInvitations::class],
    [AuthUsers::class],
    [AuthUserReader::class],
    [AuthClients::class],
    [AuthMemberships::class],
    [AuthAuditReader::class],
    [AuthMaintenance::class],
]);

it('resolves native complete operations without binding copied operation interfaces', function (): void {
    foreach ([
        Authentication::class,
        AuthenticationSessions::class,
        AuthChallenges::class,
        AuthPasswords::class,
        AuthEmailVerification::class,
        AuthInvitations::class,
        AuthUsers::class,
        AuthUserReader::class,
        AuthClients::class,
        AuthMemberships::class,
        AuthAuditReader::class,
        AuthMaintenance::class,
    ] as $class) {
        expect(app($class))->toBeInstanceOf($class)
            ->and((new ReflectionClass($class))->getInterfaceNames())->toBe([]);
    }
});

it('preserves every public extension host instance and lazy factory without changing native lifetimes', function (): void {
    config(['nvl-auth.features.passkeys.settings.origins' => ['https://auth-package.test'], 'nvl-auth.features.passkeys.settings.relying_party_id' => 'auth-package.test', 'nvl-auth.features.passkeys.settings.relying_party_name' => 'Auth tests']);
    $consumer = authContractConsumer($this->app);
    try {
        foreach (authPublicExtensionContracts() as [$contract]) {
            $host = Mockery::mock($contract);
            $consumer->instance($contract, $host);
        }
        $instances = [];
        foreach (authPublicExtensionContracts() as [$contract]) {
            $instances[$contract] = $consumer->make($contract);
        }
        (new AuthServiceProvider($consumer))->register();
        $consumer->forgetScopedInstances();
        foreach ($instances as $contract => $host) {
            expect($consumer->getBindings()[$contract] ?? null)->toBeNull();
            expect($consumer->make($contract))->toBe($host);
            $consumer->offsetUnset($contract);
            $factory = static fn (): never => throw new LogicException('A host extension must not execute at registration.');
            $consumer->bind($contract, $factory);
        }
        (new AuthServiceProvider($consumer))->register();
        foreach (authPublicExtensionContracts() as [$contract]) {
            expect($consumer->getBindings()[$contract]['shared'])->toBeFalse();
            expect(fn () => $consumer->make($contract))->toThrow(LogicException::class, 'A host extension must not execute at registration.');
        }
    } finally {
        Container::setInstance($this->app);
        $consumer->flush();
    }
    foreach (authPublicExtensionContracts() as [$contract, $scoped]) {
        $this->app->offsetUnset($contract);
    }
    (new AuthServiceProvider($this->app))->register();
    foreach (authPublicExtensionContracts() as [$contract, $scoped]) {
        $first = $this->app->make($contract);
        expect($this->app->getBindings()[$contract]['shared'])->toBeTrue()
            ->and($this->app->make($contract))->toBe($first);
        $this->app->forgetScopedInstances();
        expect($this->app->make($contract) === $first)->toBe(! $scoped);
    }
});

it('keeps host consumer orchestration outside package operations', function (): void {
    $guard = Mockery::mock(StatefulGuard::class);
    $session = Mockery::mock(Session::class);
    $guard->shouldReceive('user')->once()->andReturnNull();
    $guard->shouldReceive('logout')->once();
    $session->shouldReceive('invalidate')->once()->andReturnTrue();
    $session->shouldReceive('regenerateToken')->once();
    Event::fake();
    Queue::fake();
    Notification::fake();
    app(AuthenticationSessions::class)->logout($guard, $session);
    Queue::assertNothingPushed();
    Notification::assertNothingSent();
    Event::assertDispatched(UserLoggedOut::class);
});

it('drops scoped audit metadata across scopes and never extracts ambient request identity', function (): void {
    $this->app->forgetScopedInstances();
    $this->app->instance('request', Request::create('/first', server: ['REMOTE_ADDR' => '192.0.2.1', 'HTTP_X_REQUEST_ID' => 'request-a']));
    $first = app(AuthAuditContextProvider::class);
    expect($first->requestId())->toBeNull()->and($first->ipAddress())->toBeNull()->and($first->userAgent())->toBeNull();
    $this->app->forgetScopedInstances();
    $this->app->instance('request', Request::create('/second', server: ['HTTP_X_REQUEST_ID' => 'request-b']));
    $second = app(AuthAuditContextProvider::class);
    expect($second)->not->toBe($first)->and($second->requestId())->toBeNull();
    $other = $this->createApplication();
    try {
        expect($other->make(AuthAuditContextProvider::class))->not->toBe($second);
    } finally {
        Container::setInstance($this->app);
        Facade::setFacadeApplication($this->app);
        Facade::clearResolvedInstances();
        $other->flush();
    }
});

it('preserves explicit native owner access hosts through Auth provider registration', function (bool $hostFirst): void {
    $consumer = authContractConsumer($this->app);
    $host = Mockery::mock(OwnerAccess::class);
    try {
        if ($hostFirst) {
            $consumer->instance(OwnerAccess::class, $host);
        }
        (new AuthServiceProvider($consumer))->register();
        if (! $hostFirst) {
            $consumer->instance(OwnerAccess::class, $host);
        }
        (new AuthServiceProvider($consumer))->register();
        expect($consumer->make(OwnerAccess::class))->toBe($host);
    } finally {
        Container::setInstance($this->app);
        $consumer->flush();
    }
})->with([false, true]);

/** Build a real passive host container without using any package workflow. */
function authContractConsumer(Application $origin): Application
{
    $consumer = new Application($origin->basePath());
    $consumer->instance('config', new Repository($origin->make('config')->all()));
    $consumer->instance('env', 'testing');
    $consumer->instance('db', $origin->make('db'));
    $consumer->instance('events', $origin->make('events'));
    $consumer->instance('cache', $origin->make('cache'));
    $consumer->instance('translation.loader', $origin->make('translation.loader'));
    $consumer->make('config')->set('nvl-auth.adoption.spatie_storage.enabled', false);
    $consumer->make('config')->set('nvl-auth.adoption.principal_model.enabled', false);
    $consumer->make('config')->set('nvl-auth.adoption.password_broker.enabled', false);
    $consumer->register(FilesystemServiceProvider::class);

    return $consumer;
}

/** @return list<array{class-string, bool}> */
function authPublicExtensionContracts(): array
{
    return [
        [AuthAuditRecorder::class, true],
        [AuthManagementAccess::class, false],
        [PasswordUpdater::class, false],
        [PrincipalAttributeMapper::class, false],
        [AccountConfirmation::class, false],
        [PrincipalSessionContainment::class, false],
        [RbacPrincipalAccess::class, false],
        [SystemMutationAccess::class, false],
        [AuthSubjectResolver::class, false],
        [AuthIdentifierResolver::class, false],
        [SuccessfulLoginMetadataRecorder::class, false],
        [AuthenticationEligibility::class, false],
        [ApiTokenManager::class, false],
        [ApiTokenAbilityProvider::class, false],
        [SocialIdentityProviderFactory::class, true],
        [PasskeyCeremony::class, false],
        [InvitationSubjectResolver::class, false],
        [InvitationRegistrationMapper::class, false],
        [MembershipPrincipalResolver::class, false],
        [AuthAuditContextProvider::class, true],
        [InvitationRecipientProof::class, false],
    ];
}

it('preserves a consumer provider factory binding', function (): void {
    $consumer = authContractConsumer($this->app);
    $contract = SocialIdentityProviderFactory::class;
    $host = Mockery::mock(SocialIdentityProviderFactory::class);
    try {
        $consumer->instance($contract, $host);
        (new AuthServiceProvider($consumer))->register();
        expect($consumer->make($contract))->toBe($host)
            ->and(interface_exists($contract))->toBeTrue();
    } finally {
        Container::setInstance($this->app);
        $consumer->flush();
    }
});
