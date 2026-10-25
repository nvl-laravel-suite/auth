<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Tests\CoreOnlyTestCase;
use Nvl\Auth\Tests\Fixtures\AllowAllManagementAccess;

uses(CoreOnlyTestCase::class);

it('loads the base principal and completes core login without optional adapter providers', function (): void {
    $principal = User::query()->create(['name' => 'Core', 'email' => 'core@example.test', 'password' => 'correct-password']);
    expect(method_exists($principal, 'tokens'))->toBeFalse()->and(method_exists($principal, 'roles'))->toBeFalse();
    $session = app('session.store');
    $session->start();
    $guard = auth()->guard('web');
    $authenticated = app(Authentication::class)->login(['identifier' => 'core@example.test', 'password' => 'correct-password'], [], $guard, $session);
    expect($authenticated->getAuthIdentifier())->toBe($principal->id)->and($guard->id())->toBe($principal->id);
});

it('defaults management to deny and admits an explicit host authority without RBAC or Sanctum', function (): void {
    $actor = User::query()->create(['name' => 'Actor', 'email' => 'actor@example.test', 'password' => 'correct-password']);
    $input = ['name' => 'New user', 'email' => 'new@example.test', 'password' => 'correct-password'];
    try {
        app(AuthUsers::class)->create($actor, $input);
        throw new RuntimeException('Expected denial');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('forbidden');
    }
    app()->instance(AuthManagementAccess::class, new AllowAllManagementAccess);
    $created = app(AuthUsers::class)->create($actor, $input);
    expect($created->email)->toBe('new@example.test')->and($created->getRelations())->toBe([]);
});

it('rejects disabled passkeys before constructing any optional engine', function (): void {
    app()->bind(PasskeyCeremony::class, static function (): never {
        throw new RuntimeException('The optional engine must remain unresolved.');
    });
    DB::enableQueryLog();
    expect(fn () => app(AuthPasskeys::class)->beginAuthentication())->toThrow(AuthException::class, 'unavailable')
        ->and(DB::getQueryLog())->toBe([]);
});
