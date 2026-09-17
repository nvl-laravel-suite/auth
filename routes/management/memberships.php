<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Controllers\Management\MembershipController;
use Nvl\Tenancy\Http\Middleware\RequireTenantMembership;

Route::middleware(RequireTenantMembership::class)->group(function (): void {
    Route::get('memberships', [MembershipController::class, 'index'])->name('memberships.index');
    Route::post('memberships', [MembershipController::class, 'store'])->name('memberships.store');
    Route::get('memberships/{membership}', [MembershipController::class, 'show'])->whereUuid('membership')->name('memberships.show');
    Route::patch('memberships/{membership}/status', [MembershipController::class, 'status'])->whereUuid('membership')->name('memberships.status');
    Route::delete('memberships/{membership}', [MembershipController::class, 'destroy'])->whereUuid('membership')->name('memberships.destroy');
    Route::post('memberships/{membership}/transfer-ownership', [MembershipController::class, 'transfer'])->whereUuid('membership')->name('memberships.transfer_ownership');
});
