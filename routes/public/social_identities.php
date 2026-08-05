<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\SocialIdentityController;

Route::get('social/{provider}/redirect', [SocialIdentityController::class, 'redirect'])
    ->where('provider', '[a-z][a-z0-9_.-]{0,79}')
    ->middleware('nvl-auth.feature:social_identities,issue')
    ->name('social.redirect');
Route::get('social/{provider}/callback', [SocialIdentityController::class, 'callback'])
    ->where('provider', '[a-z][a-z0-9_.-]{0,79}')
    ->middleware('nvl-auth.feature:social_identities,use')
    ->name('social.callback');
