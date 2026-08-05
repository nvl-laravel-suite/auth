<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\TotpController;

Route::post('totp/enroll', [TotpController::class, 'start'])
    ->middleware('nvl-auth.feature:totp,enroll')
    ->name('totp.enroll');
Route::post('totp/{credential}/confirm', [TotpController::class, 'confirm'])
    ->whereUuid('credential')
    ->middleware('nvl-auth.feature:totp,enroll')
    ->name('totp.confirm');
Route::post('totp/verify', [TotpController::class, 'verify'])
    ->middleware('nvl-auth.feature:totp,use')
    ->name('totp.verify');
Route::delete('totp/{credential}', [TotpController::class, 'revoke'])
    ->whereUuid('credential')
    ->middleware('nvl-auth.feature:totp,revoke')
    ->name('totp.revoke');
