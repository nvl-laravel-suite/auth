<?php

declare(strict_types=1);

use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('exposes central self discovery without accepting tenant ownership input', function (): void {
    $scenario = new AuthTenancyScenario;
    $member = $this->user('http-member@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($member));
    $scenario->member($scenario->b(), SubjectReference::fromAuthenticatable($member));

    $this->actingAs($member)
        ->getJson(route('nvl.auth.account.memberships.index'))
        ->assertOk()
        ->assertJsonPath('code', 'memberships_listed')
        ->assertJsonCount(2, 'data')
        ->assertJsonMissingPath('data.0.email');
});

it('admits tenant management before lookup and hides foreign membership identifiers', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('http-owner@example.test');
    $target = $this->user('http-target@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $foreign = $scenario->member($scenario->b(), SubjectReference::fromAuthenticatable($target));

    $this->actingAs($owner)
        ->getJson(route('nvl.auth.management.memberships.show', ['membership' => $foreign->id]))
        ->assertNotFound();

    $this->actingAs($owner)
        ->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->getJson(route('nvl.auth.management.memberships.show', ['membership' => $foreign->id]))
        ->assertNotFound();

    $this->actingAs($owner)
        ->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->postJson(route('nvl.auth.management.memberships.store'), [
            'tenant_id' => $scenario->b()->value,
            'is_owner' => true,
        ])
        ->assertUnprocessable();
});
