<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\PasswordController;

Route::post('password/forgot', [PasswordController::class, 'requestReset'])
    ->middleware('nvl-auth.feature:password,issue')
    ->name('password.request');
Route::post('password/reset', [PasswordController::class, 'reset'])
    ->middleware('nvl-auth.feature:password,use')
    ->name('password.reset');
