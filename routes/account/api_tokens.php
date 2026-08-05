<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\ApiTokenController;

Route::get('api-tokens', [ApiTokenController::class, 'index'])
    ->middleware('nvl-auth.feature:api_tokens,read')
    ->name('api_tokens.index');
Route::post('api-tokens', [ApiTokenController::class, 'store'])
    ->middleware('nvl-auth.feature:api_tokens,issue')
    ->name('api_tokens.store');
Route::put('api-tokens/{tokenId}', [ApiTokenController::class, 'update'])
    ->middleware('nvl-auth.feature:api_tokens,update')
    ->name('api_tokens.update');
Route::post('api-tokens/{tokenId}/rotate', [ApiTokenController::class, 'rotate'])
    ->middleware('nvl-auth.feature:api_tokens,update')
    ->name('api_tokens.rotate');
Route::delete('api-tokens/{tokenId}', [ApiTokenController::class, 'destroy'])
    ->middleware('nvl-auth.feature:api_tokens,revoke')
    ->name('api_tokens.destroy');
Route::delete('api-tokens', [ApiTokenController::class, 'destroyAll'])
    ->middleware('nvl-auth.feature:api_tokens,revoke')
    ->name('api_tokens.destroy_all');
