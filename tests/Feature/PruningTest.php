<?php

declare(strict_types=1);

use Nvl\Auth\Actions\PruneAuthStateAction;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\Passkey;

it('dry-runs and prunes only old terminal state while retaining audits', function (): void {
    config()->set('nvl-auth.cleanup.retention_days', 30);
    $invitation = Invitation::factory()->create([
        'expires_at' => now()->subDays(40),
        'created_at' => now()->subDays(40),
        'updated_at' => now()->subDays(40),
    ]);
    $passkey = Passkey::factory()->create(['revoked_at' => now()->subDays(40)]);
    $audit = AuthAudit::factory()->create(['created_at' => now()->subDays(100)]);
    $action = app(PruneAuthStateAction::class);

    expect($action->execute(true)['invitations'])->toBe(1)
        ->and(Invitation::query()->whereKey($invitation->identifier())->exists())->toBeTrue();

    $counts = $action->execute();

    expect($counts['invitations'])->toBe(1)
        ->and($counts['passkeys'])->toBe(1)
        ->and(Invitation::query()->whereKey($invitation->identifier())->exists())->toBeFalse()
        ->and(Passkey::query()->whereKey($passkey->identifier())->exists())->toBeFalse()
        ->and(AuthAudit::query()->whereKey($audit->identifier())->exists())->toBeTrue();
});
