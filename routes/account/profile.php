<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\ProfileController;

Route::get('profile', [ProfileController::class, 'show'])
    ->middleware('nvl-auth.feature:principal_management,read')
    ->name('profile.show');
Route::patch('profile', [ProfileController::class, 'update'])
    ->middleware('nvl-auth.feature:principal_management,update')
    ->name('profile.update');
Route::delete('profile', [ProfileController::class, 'destroy'])
    ->middleware([
        'nvl-auth.feature:principal_management,revoke',
        'nvl-auth.feature:sessions,revoke',
    ])
    ->name('profile.destroy');
