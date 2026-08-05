<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\ChallengeController;

Route::post('magic-links', [ChallengeController::class, 'requestMagicLink'])
    ->middleware('nvl-auth.feature:magic_links,issue')
    ->name('magic_links.request');
Route::post('magic-links/consume', [ChallengeController::class, 'consumeMagicLink'])
    ->middleware('nvl-auth.feature:magic_links,use')
    ->name('magic_links.consume');
