<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Public\ClientController;

Route::post('clients/start', [ClientController::class, 'start'])
    ->middleware('nvl-auth.feature:clients,use')
    ->name('clients.start');
