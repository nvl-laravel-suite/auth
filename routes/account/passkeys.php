<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\PasskeyController;

Route::post('passkeys/registration/options', [PasskeyController::class, 'begin'])
    ->middleware('nvl-auth.feature:passkeys,enroll')
    ->name('passkeys.registration.options');
Route::post('passkeys/registration', [PasskeyController::class, 'finish'])
    ->middleware('nvl-auth.feature:passkeys,enroll')
    ->name('passkeys.registration.finish');
Route::delete('passkeys/{passkey}', [PasskeyController::class, 'revoke'])
    ->whereUuid('passkey')
    ->middleware('nvl-auth.feature:passkeys,revoke')
    ->name('passkeys.revoke');
