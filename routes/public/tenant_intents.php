<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\TenantAuthenticationIntentController;

Route::post('tenant-intents/complete', [TenantAuthenticationIntentController::class, 'complete'])
    ->middleware(['nvl-auth.guard', 'nvl-auth.feature:sessions,use'])
    ->name('tenant_intents.complete');
