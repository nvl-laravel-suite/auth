<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Management\UserController;

Route::get('users', [UserController::class, 'index'])
    ->middleware('nvl-auth.feature:principal_management,read')
    ->name('users.index');
Route::get('users/suggestions', [UserController::class, 'suggestions'])
    ->middleware('nvl-auth.feature:principal_management,read')
    ->name('users.suggestions');
Route::post('users/bulk', [UserController::class, 'bulk'])
    ->middleware('nvl-auth.feature:principal_management,update')
    ->name('users.bulk');
Route::post('users', [UserController::class, 'store'])
    ->middleware('nvl-auth.feature:principal_management,issue')
    ->name('users.store');
Route::get('users/{user}', [UserController::class, 'show'])
    ->whereUuid('user')
    ->middleware('nvl-auth.feature:principal_management,read')
    ->name('users.show');
Route::put('users/{user}', [UserController::class, 'update'])
    ->whereUuid('user')
    ->middleware('nvl-auth.feature:principal_management,update')
    ->name('users.update');
Route::patch('users/{user}/status', [UserController::class, 'status'])
    ->whereUuid('user')
    ->middleware('nvl-auth.feature:principal_management,update')
    ->name('users.status');
Route::put('users/{user}/roles', [UserController::class, 'roles'])
    ->whereUuid('user')
    ->middleware(['nvl-auth.feature:principal_management,update', 'nvl-auth.feature:rbac,update'])
    ->name('users.roles');
Route::put('users/{user}/permissions', [UserController::class, 'permissions'])
    ->whereUuid('user')
    ->middleware(['nvl-auth.feature:principal_management,update', 'nvl-auth.feature:rbac,update'])
    ->name('users.permissions');
Route::post('users/{user}/restore', [UserController::class, 'restore'])
    ->whereUuid('user')
    ->middleware('nvl-auth.feature:principal_management,revoke')
    ->name('users.restore');
Route::delete('users/{user}', [UserController::class, 'destroy'])
    ->whereUuid('user')
    ->middleware('nvl-auth.feature:principal_management,revoke')
    ->name('users.destroy');
