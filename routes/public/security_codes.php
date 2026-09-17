<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\ChallengeController;

Route::post('security-codes', [ChallengeController::class, 'requestSecurityCode'])
    ->middleware('nvl-auth.feature:security_codes,issue')
    ->name('security_codes.request');
Route::post('security-codes/verify', [ChallengeController::class, 'verifySecurityCode'])
    ->middleware('nvl-auth.feature:security_codes,use')
    ->name('security_codes.verify');
Route::post('security-codes/authentication', [ChallengeController::class, 'requestSecurityCodeAuthentication'])
    ->middleware(['nvl-auth.feature:security_codes,issue', 'nvl-auth.feature:sessions,use'])
    ->name('security_codes.authentication.request');
Route::post('security-codes/authentication/verify', [ChallengeController::class, 'verifySecurityCodeAuthentication'])
    ->middleware(['nvl-auth.feature:security_codes,use', 'nvl-auth.feature:sessions,use'])
    ->name('security_codes.authentication.verify');
