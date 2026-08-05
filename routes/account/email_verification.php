<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\AuthenticationController;

Route::post('email/verification', [AuthenticationController::class, 'requestEmailVerification'])
    ->middleware('nvl-auth.feature:email_verification,issue')
    ->name('email.request');
