<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Models\OwnerAuthenticationIntent;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\OwnerMembershipLock;
use Nvl\Auth\Tests\LegacyOwnerAdoptionTestCase;
use Nvl\Ownership\Services\OwnershipAdoptionCoordinator;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;

uses(LegacyOwnerAdoptionTestCase::class);

it('stages historical Auth identities without rewriting legacy facts or granting suspended membership', function (): void {
    app(OwnershipRunner::class)->run(Company::findOrFail(7), Actor::findOrFail(1), function (): void {
        $membership = OwnerMembership::findOrFail(LegacyOwnerAdoptionTestCase::Membership);
        expect($membership->status->value)->toBe('suspended')->and($membership->revision)->toBe(4294967301)
            ->and($membership->is_owner)->toBeTrue()->and($membership->subject_id)->toBe('1')
            ->and(OwnerMembershipLock::sole()->id)->toBe(LegacyOwnerAdoptionTestCase::Tenant)
            ->and(OwnerAuthenticationIntent::sole()->nonce_hash)->toBe(str_repeat('a', 64));
    });
    app(OwnershipRunner::class)->run(Company::findOrFail(8), Actor::findOrFail(1), function (): void {
        expect(OwnerMembership::count())->toBe(0)->and(OwnerAuthenticationIntent::count())->toBe(0);
    });
    expect(DB::table('nvl_auth_tenant_memberships')->where('id', LegacyOwnerAdoptionTestCase::Membership)->value('revision'))->toBe(4294967301)
        ->and(DB::table('nvl_auth_tenant_memberships')->where('id', LegacyOwnerAdoptionTestCase::Membership)->value('status'))->toBe('suspended')
        ->and(DB::table('nvl_auth_tenant_authentication_intents')->count())->toBe(1);
});

it('detects historical status drift rather than certifying a different authorization set', function (): void {
    DB::table('nvl_auth_tenant_memberships')->where('id', LegacyOwnerAdoptionTestCase::Membership)->update(['status' => 'revoked']);
    expect(fn () => app(OwnershipAdoptionCoordinator::class)->verify($this->adoptionPlan))->toThrow(OwnershipConfigurationInvalid::class);
});

it('refuses to certify a pending legacy authentication proof as native admission', function (): void {
    DB::table('nvl_auth_tenant_authentication_intents')->where('id', LegacyOwnerAdoptionTestCase::Intent)->update(['consumed_at' => null, 'expires_at' => now()->addHour()]);
    expect(fn () => app(OwnershipAdoptionCoordinator::class)->verify($this->adoptionPlan))
        ->toThrow(OwnershipConfigurationInvalid::class, 'Pending historical authentication intents must drain or expire');
});
