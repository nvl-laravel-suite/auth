<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Management\AuditController;

Route::get('audits', [AuditController::class, 'index'])
    ->middleware('nvl-auth.feature:audit,read')
    ->name('audits.index');
Route::get('audits/{authAudit}', [AuditController::class, 'show'])
    ->whereUuid('authAudit')
    ->middleware('nvl-auth.feature:audit,read')
    ->name('audits.show');
