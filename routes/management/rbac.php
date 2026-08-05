<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Management\PermissionController;
use Nvl\Auth\Http\Controllers\Management\RbacController;
use Nvl\Auth\Http\Controllers\Management\RoleController;

Route::post('rbac/synchronize', [RbacController::class, 'synchronize'])
    ->middleware('nvl-auth.feature:rbac,update')
    ->name('rbac.synchronize');

Route::get('roles', [RoleController::class, 'index'])->middleware('nvl-auth.feature:rbac,read')->name('roles.index');
Route::get('roles/hierarchy', [RoleController::class, 'hierarchy'])->middleware('nvl-auth.feature:rbac,read')->name('roles.hierarchy');
Route::get('roles/templates', [RoleController::class, 'templates'])->middleware('nvl-auth.feature:rbac,read')->name('roles.templates');
Route::get('roles/analytics', [RoleController::class, 'analytics'])->middleware('nvl-auth.feature:rbac,read')->name('roles.analytics');
Route::post('roles/apply-template', [RoleController::class, 'applyTemplate'])->middleware('nvl-auth.feature:rbac,update')->name('roles.apply_template');
Route::post('roles', [RoleController::class, 'store'])->middleware('nvl-auth.feature:rbac,issue')->name('roles.store');
Route::get('roles/{role}', [RoleController::class, 'show'])->whereUuid('role')->middleware('nvl-auth.feature:rbac,read')->name('roles.show');
Route::put('roles/{role}', [RoleController::class, 'update'])->whereUuid('role')->middleware('nvl-auth.feature:rbac,update')->name('roles.update');
Route::post('roles/{role}/clone', [RoleController::class, 'clone'])->whereUuid('role')->middleware('nvl-auth.feature:rbac,issue')->name('roles.clone');
Route::delete('roles/{role}', [RoleController::class, 'destroy'])->whereUuid('role')->middleware('nvl-auth.feature:rbac,revoke')->name('roles.destroy');

Route::get('permissions', [PermissionController::class, 'index'])->middleware('nvl-auth.feature:rbac,read')->name('permissions.index');
Route::post('permissions', [PermissionController::class, 'store'])->middleware('nvl-auth.feature:rbac,issue')->name('permissions.store');
Route::get('permissions/{permission}', [PermissionController::class, 'show'])->whereUuid('permission')->middleware('nvl-auth.feature:rbac,read')->name('permissions.show');
Route::put('permissions/{permission}', [PermissionController::class, 'update'])->whereUuid('permission')->middleware('nvl-auth.feature:rbac,update')->name('permissions.update');
Route::delete('permissions/{permission}', [PermissionController::class, 'destroy'])->whereUuid('permission')->middleware('nvl-auth.feature:rbac,revoke')->name('permissions.destroy');
