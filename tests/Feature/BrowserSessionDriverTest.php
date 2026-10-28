<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Session\DatabaseSessionHandler;
use Illuminate\Session\FileSessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Adapters\Laravel\LaravelSessionAdmission;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Services\Authentication;

it('admits a real persisted driver round trip and denies a revoked payload before application work', function (string $driver): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'session.driver' => $driver]);
    $files = new Filesystem;
    $directory = sys_get_temp_dir().'/nvl-auth-managed-'.bin2hex(random_bytes(8));
    if ($driver === 'database') {
        Schema::create('native_managed_test_sessions', function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('user_id')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->text('payload');
            $table->integer('last_activity');
        });
        $handler = new DatabaseSessionHandler(app('db')->connection(), 'native_managed_test_sessions', 120, app());
    } else {
        $files->makeDirectory($directory);
        $handler = new FileSessionHandler($files, $directory, 120);
    }
    try {
        $store = new Store('managed', $handler);
        $store->start();
        app()->instance('session.store', $store);
        auth()->forgetGuards();
        $user = $this->user();
        $guard = auth()->guard('web');
        app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $store);
        $store->save();
        $recovered = new Store('managed', $handler, $store->getId());
        $recovered->start();
        app()->instance('session.store', $recovered);
        auth()->forgetGuards();
        $guard = auth()->guard('web');
        app(LaravelSessionAdmission::class)->admit($guard, $recovered, 'web');
        expect($guard->id())->toBe($user->getAuthIdentifier());
        BrowserSession::query()->update(['revoked_at' => now()]);
        expect(fn () => app(LaravelSessionAdmission::class)->admit($guard, $recovered, 'web'))->toThrow(AuthException::class);
        expect($guard->check())->toBeFalse();
    } finally {
        if ($files->isDirectory($directory)) {
            $files->deleteDirectory($directory);
        }
    }
})->with(['file', 'database']);
