<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Tests\Fixtures\Actor;

/** Host fixture for retained isolation and protocol scenarios on native ownership. */
abstract class NativeOwnerScenarioTestCase extends OwnerScopeTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->app->bind(OwnerAccess::class, static fn () => new class implements OwnerAccess
        {
            public function assertCanEnter(Authenticatable $actor, Model $owner): void
            {
                if ($actor instanceof Actor && $actor->getAuthIdentifier() === 1) {
                    return;
                }
                app(AuthOwnerAccess::class)->assertCanEnter($actor, $owner);
            }
        });
    }

    protected function user(string $email = 'user@example.test'): TestUser
    {
        return TestUser::query()->create(['name' => 'Test user', 'email' => $email, 'password' => 'correct-password']);
    }
}
