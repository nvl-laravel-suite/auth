<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\SocialIdentityController;

Route::get('social/{provider}/link', [SocialIdentityController::class, 'redirect'])
    ->where('provider', '[a-z][a-z0-9_.-]{0,79}')
    ->middleware('nvl-auth.feature:social_identities,enroll')
    ->name('social.link');
Route::get('social/{provider}/link/callback', [SocialIdentityController::class, 'callback'])
    ->where('provider', '[a-z][a-z0-9_.-]{0,79}')
    ->middleware('nvl-auth.feature:social_identities,enroll')
    ->name('social.link.callback');
Route::delete('social-identities/{socialIdentity}', [SocialIdentityController::class, 'destroy'])
    ->whereUuid('socialIdentity')
    ->middleware('nvl-auth.feature:social_identities,revoke')
    ->name('social.destroy');
