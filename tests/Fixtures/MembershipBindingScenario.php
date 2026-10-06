<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Filesystem\FilesystemServiceProvider;
use Illuminate\Foundation\Application;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthTenantMembershipAccess;
use Nvl\Data\Services\TypeScriptSourceRegistry;
use Nvl\Support\Providers\TenantServiceProvider;
use Nvl\Support\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Support\Tenancy\ValueObjects\TenantId;
use Nvl\Tenancy\Providers\TenancyServiceProvider;

/** Shared consumer scenario for Core fallback and explicit optional Tenancy provider orders. */
final class MembershipBindingScenario
{
    /** Prove replacement, lifetime, and host preservation in one isolated passive container. */
    public static function assertNativeOverride(Application $origin, bool $resolved, string $order): void
    {
        $consumer = self::consumer($origin);
        try {
            $provider = new AuthServiceProvider($consumer);
            if ($order === 'core first') {
                $consumer->register(TenantServiceProvider::class);
            } elseif ($order === 'tenancy first') {
                $consumer->register(TenancyServiceProvider::class);
            }
            $provider->register();
            if ($order === 'auth first') {
                $consumer->register(TenancyServiceProvider::class);
            }
            $old = $resolved ? $consumer->make(TenantMembershipAccess::class) : null;
            expect($consumer->isShared(TenantMembershipAccess::class))->toBeFalse();
            $factoryResolutions = 0;
            $consumer->beforeResolving(AuthTenantMembershipAccess::class, static function () use (&$factoryResolutions): void {
                $factoryResolutions++;
            });
            if ($resolved) {
                $consumer->rebinding(TenantMembershipAccess::class, static function (): void {});
            }
            self::boot($consumer, $origin);
            expect($factoryResolutions)->toBe(0);
            $current = $consumer->make(TenantMembershipAccess::class);
            expect($current)->toBeInstanceOf(AuthTenantMembershipAccess::class)
                ->and($consumer->make(TenantMembershipAccess::class))->toBe($current);
            if ($resolved) {
                expect($old)->not->toBe($current);
            }
            $host = new class implements TenantMembershipAccess
            {
                public function assertMember(Authenticatable $actor, TenantId $tenant): void {}
            };
            $consumer->instance(TenantMembershipAccess::class, $host);
            self::boot($consumer, $origin);
            expect($consumer->make(TenantMembershipAccess::class))->toBe($host);
            $consumer->forgetScopedInstances();
            expect($consumer->make(TenantMembershipAccess::class))->toBeInstanceOf(AuthTenantMembershipAccess::class)->not->toBe($current);
        } finally {
            Container::setInstance($origin);
            $consumer->flush();
        }
    }

    /** Construct the passive host used by each provider-order proof. */
    private static function consumer(Application $origin): Application
    {
        $consumer = new Application($origin->basePath());
        $consumer->instance('config', new Repository($origin->make('config')->all()));
        $consumer->instance('env', 'testing');
        $consumer->instance('db', $origin->make('db'));
        $consumer->instance('events', $origin->make('events'));
        $consumer->instance('cache', $origin->make('cache'));
        $consumer->instance('translation.loader', $origin->make('translation.loader'));
        $consumer->make('config')->set('nvl-tenancy.directory.driver', 'package');
        $consumer->make('config')->set('nvl-auth.adoption.spatie_storage.enabled', false);
        $consumer->make('config')->set('nvl-auth.adoption.principal_model.enabled', false);
        $consumer->make('config')->set('nvl-auth.adoption.password_broker.enabled', false);
        $consumer->register(FilesystemServiceProvider::class);

        return $consumer;
    }

    /** Enable only membership binding while retaining host storage and adoption. */
    private static function boot(Application $consumer, Application $origin): void
    {
        $consumer->make('config')->set('nvl-tenancy.enabled', true);
        $consumer->make('config')->set('nvl-auth.features.memberships.enabled', true);
        $consumer->make('config')->set('nvl-auth.features.rbac.enabled', false);
        $consumer->make('config')->set('nvl-auth.migrations.enabled', false);
        $consumer->make('config')->set('nvl-auth.adoption.spatie_storage.enabled', false);
        $consumer->instance(HttpKernelContract::class, $origin->make(HttpKernelContract::class));
        $consumer->instance(MembershipPrincipalResolver::class, $origin->make(MembershipPrincipalResolver::class));
        (new AuthServiceProvider($consumer))->boot($consumer->make(AuthConfiguration::class), $consumer->make(TypeScriptSourceRegistry::class));
    }
}
