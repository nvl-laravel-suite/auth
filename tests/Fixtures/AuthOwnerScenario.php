<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Contracts\CentralAccess;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Creates admitted native-owner arrangements through real membership mutations. */
final class AuthOwnerScenario
{
    public function a(): OwnerReference
    {
        return app(OwnerIdentityResolver::class)->reference(Company::query()->findOrFail(7));
    }

    public function b(): OwnerReference
    {
        return app(OwnerIdentityResolver::class)->reference(Company::query()->findOrFail(8));
    }

    public function run(OwnerReference $owner, Closure $operation): mixed
    {
        return app(OwnershipRunner::class)->run(app(OwnerIdentityResolver::class)->resolve($owner), Actor::query()->findOrFail(1), $operation);
    }

    public function platform(Closure $operation): mixed
    {
        config(['nvl-ownership.central_operations' => ['auth-test.setup']]);
        app()->bind(CentralAccess::class, static fn () => new class implements CentralAccess
        {
            public function assertCanRun(string $operation, Authenticatable $actor): void {}
        });

        return app(OwnershipRunner::class)->central('auth-test.setup', Actor::query()->findOrFail(1), $operation);
    }

    public function member(OwnerReference $owner, SubjectReference $subject, bool $administrator = false): OwnerMembership
    {
        return $this->run($owner, function () use ($subject, $administrator): OwnerMembership {
            $authority = new SystemMutationContext('Native membership fixture', 'fixture');
            $memberships = app(AuthMemberships::class);
            if ($administrator) {
                return $memberships->provision($authority, $subject);
            }

            return (new OwnerMembership)->getConnection()->transaction(function () use ($memberships, $authority, $subject): OwnerMembership {
                $memberships->lock(true);

                return $memberships->enroll($authority, $subject);
            });
        });
    }
}
