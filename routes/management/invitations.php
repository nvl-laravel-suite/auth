<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Management\InvitationController;

Route::get('invitations', [InvitationController::class, 'index'])
    ->middleware('nvl-auth.feature:invitations,read')
    ->name('invitations.index');
Route::post('invitations', [InvitationController::class, 'store'])
    ->middleware('nvl-auth.feature:invitations,issue')
    ->name('invitations.store');
Route::post('invitations/{invitation}/resend', [InvitationController::class, 'resend'])
    ->whereUuid('invitation')
    ->middleware('nvl-auth.feature:invitations,issue')
    ->name('invitations.resend');
Route::delete('invitations/{invitation}', [InvitationController::class, 'destroy'])
    ->whereUuid('invitation')
    ->middleware('nvl-auth.feature:invitations,revoke')
    ->name('invitations.destroy');
