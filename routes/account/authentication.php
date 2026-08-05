<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\AuthenticationController;

Route::post('logout', [AuthenticationController::class, 'logout'])
    ->middleware('nvl-auth.feature:authentication,revoke')
    ->name('logout');
