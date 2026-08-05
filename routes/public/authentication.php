<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\AuthenticationController;

Route::post('login', [AuthenticationController::class, 'login'])
    ->middleware('nvl-auth.feature:authentication,use')
    ->name('login');
