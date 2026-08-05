<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\InvitationController;

Route::post('invitations/accept', [InvitationController::class, 'accept'])
    ->middleware('nvl-auth.feature:invitations,use')
    ->name('invitations.accept');
