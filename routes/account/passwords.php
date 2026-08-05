<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\AuthenticationController;

Route::put('password', [AuthenticationController::class, 'updatePassword'])
    ->middleware('nvl-auth.feature:password,update')
    ->name('password.update');
Route::post('password/confirm', [AuthenticationController::class, 'confirmPassword'])
    ->middleware([
        'nvl-auth.feature:password,use',
        'nvl-auth.feature:sessions,use',
    ])
    ->name('password.confirm');
