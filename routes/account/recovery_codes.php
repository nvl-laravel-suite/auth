<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Account\RecoveryCodeController;

Route::post('recovery-codes/regenerate', [RecoveryCodeController::class, 'regenerate'])
    ->middleware('nvl-auth.feature:recovery_codes,issue')
    ->name('recovery_codes.regenerate');
Route::post('recovery-codes/consume', [RecoveryCodeController::class, 'consume'])
    ->middleware('nvl-auth.feature:recovery_codes,use')
    ->name('recovery_codes.consume');
Route::delete('recovery-codes', [RecoveryCodeController::class, 'revoke'])
    ->middleware('nvl-auth.feature:recovery_codes,revoke')
    ->name('recovery_codes.revoke');
