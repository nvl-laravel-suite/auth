<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\MembershipController;

Route::get('account/memberships', [MembershipController::class, 'index'])
    ->middleware('nvl-auth.feature:memberships,read')
    ->name('memberships.index');
