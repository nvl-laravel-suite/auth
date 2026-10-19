<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Nvl\Auth\Ownership\LegacyAuthOwnershipMapper;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;

uses(OwnerScopeTestCase::class);

it('plans legacy membership identities from explicit native mappings without mutating either graph', function (): void {
    Schema::create('nvl_auth_tenant_memberships', static function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->uuid('tenant_id');
        $table->string('subject_type');
        $table->string('subject_id');
        $table->string('status');
        $table->boolean('is_owner');
        $table->unsignedInteger('revision');
        $table->timestamps();
    });
    $tenant = (string) Str::uuid();
    $id = (string) Str::uuid();
    DB::table('nvl_auth_tenant_memberships')->insert(['id' => $id, 'tenant_id' => $tenant, 'subject_type' => 'existing-principal', 'subject_id' => 'preserved', 'status' => 'suspended', 'is_owner' => true, 'revision' => 9]);
    $owner = app(OwnerIdentityResolver::class)->reference(Company::query()->findOrFail(7));
    $mapper = app(LegacyAuthOwnershipMapper::class);
    expect(fn () => iterator_to_array($mapper->mappings([])))->toThrow(OwnershipConfigurationInvalid::class);
    $mappings = iterator_to_array($mapper->mappings([$tenant => $owner]));
    $membership = array_values(array_filter($mappings, static fn ($mapping): bool => $mapping->resource === 'auth.memberships'));
    expect($membership)->toHaveCount(1)
        ->and($membership[0]->recordId)->toBe($id)
        ->and($membership[0]->legacyTenantId)->toBe($tenant)
        ->and($membership[0]->owner)->toEqual($owner)
        ->and($membership[0]->metadata['legacy_source_table'])->toBe('nvl_auth_tenant_memberships')
        ->and(DB::table('nvl_auth_owner_memberships')->count())->toBe(0)
        ->and(DB::table('nvl_auth_tenant_memberships')->where('id', $id)->value('revision'))->toBe(9);
});
