<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope;

require $argv[1].'/vendor/autoload.php';
$app = require $argv[1].'/bootstrap/app.php';
if (! $app instanceof Application) {
    throw new RuntimeException('Invalid Auth worker consumer application.');
}
$app->make(Kernel::class)->bootstrap();
Schema::create('jobs', static function (Blueprint $table): void {
    $table->id();
    $table->string('queue')->index();
    $table->longText('payload');
    $table->unsignedTinyInteger('attempts');
    $table->unsignedInteger('reserved_at')->nullable();
    $table->unsignedInteger('available_at');
    $table->unsignedInteger('created_at');
});
Schema::create('nvl_auth_test_delivery_receipts', static function (Blueprint $table): void {
    $table->id();
    $table->string('owner_key');
    $table->string('message_id');
    $table->unsignedTinyInteger('attempt');
});
Schema::create('failed_jobs', static function (Blueprint $table): void {
    $table->id();
    $table->string('uuid')->unique();
    $table->text('connection');
    $table->text('queue');
    $table->longText('payload');
    $table->longText('exception');
    $table->timestamp('failed_at')->useCurrent();
});
Schema::create('nvl_auth_test_worker_scopes', static function (Blueprint $table): void {
    $table->id();
    $table->string('mode');
});

Schema::create('ownership_test_companies', static function (Blueprint $table): void {
    $table->id();
    $table->boolean('active');
});
Schema::create('ownership_test_actors', static function (Blueprint $table): void {
    $table->id();
    $table->string('name');
});
$actor = Actor::query()->create(['id' => 1, 'name' => 'Operator']);
foreach ([7 => 'delivery-a', 8 => 'delivery-b'] as $key => $message) {
    $owner = Company::query()->create(['id' => $key, 'active' => true]);
    app(OwnershipRunner::class)->run($owner, $actor, static function () use ($message): void {
        Event::dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(
            messageId: $message,
            feature: AuthFeature::Invitations,
            type: AuthMessageType::Invitation,
            recipient: $message.'@example.test',
            payload: [],
            expiresAt: CarbonImmutable::now()->addHour(),
        ), OwnershipJobEnvelope::capture(app(OwnershipContext::class))));
    });
}

if (! Event::hasListeners(AuthDeliveryRequested::class)) {
    throw new RuntimeException('The Auth delivery worker listeners were not registered.');
}
if (DB::table('jobs')->count() !== 4) {
    throw new RuntimeException('The Auth delivery worker listeners were not queued.');
}
