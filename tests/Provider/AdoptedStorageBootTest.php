<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Exceptions\AuthException;
use Spatie\Permission\PermissionRegistrar;

it('boots fresh adopted storage without probing tables and denies use until migrated', function (): void {
    expect(app()->isBooted())->toBeTrue()
        ->and(config('permission.table_names.permissions'))->toBe(AuthTables::get(AuthTables::Permissions))
        ->and(DB::getQueryLog())->toBe([]);

    expect(fn () => app(PermissionRegistrar::class))->toThrow(AuthException::class, 'readiness');
});
