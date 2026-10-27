<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public\EmailVerificationController;

Route::get('email/verify/{id}', [EmailVerificationController::class, 'verify'])
    ->middleware(['nvl.auth.feature:email_verification,use'])
    ->name('email.verify');
