<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Management\ClientController;

Route::get('clients', [ClientController::class, 'index'])
    ->middleware('nvl-auth.feature:clients,read')
    ->name('clients.index');
Route::post('clients', [ClientController::class, 'store'])
    ->middleware('nvl-auth.feature:clients,issue')
    ->name('clients.store');
Route::get('clients/{client}', [ClientController::class, 'show'])
    ->whereUuid('client')
    ->middleware('nvl-auth.feature:clients,read')
    ->name('clients.show');
Route::put('clients/{client}', [ClientController::class, 'update'])
    ->whereUuid('client')
    ->middleware('nvl-auth.feature:clients,update')
    ->name('clients.update');
Route::patch('clients/{client}/status', [ClientController::class, 'status'])
    ->whereUuid('client')
    ->middleware('nvl-auth.feature:clients,update')
    ->name('clients.status');
Route::delete('clients/{client}', [ClientController::class, 'destroy'])
    ->whereUuid('client')
    ->middleware('nvl-auth.feature:clients,revoke')
    ->name('clients.destroy');
