<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\PasskeyController;

Route::post('passkeys/authentication/options', [PasskeyController::class, 'begin'])
    ->middleware('nvl-auth.feature:passkeys,use')
    ->name('passkeys.authentication.options');
Route::post('passkeys/authentication', [PasskeyController::class, 'finish'])
    ->middleware('nvl-auth.feature:passkeys,use')
    ->name('passkeys.authentication.finish');
