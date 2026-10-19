<?php

declare(strict_types=1);

use Nvl\Auth\Services\AuthOwnerContextParticipant;
use Nvl\Auth\Tests\TestCase;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;
use Nvl\Support\Ownership\ValueObjects\OwnershipSnapshot;
use Spatie\Permission\PermissionRegistrar;

uses(TestCase::class);

it('restores owner teams after nested scopes and an exception', function (): void {
    $registrar = app(PermissionRegistrar::class);
    $registrar->setPermissionsTeamId('previous-team');
    $participant = app(AuthOwnerContextParticipant::class);
    $first = new OwnerReference('company', 'store-a', 'int', '7');
    $second = new OwnerReference('company', 'store-a', 'int', '8');
    $enter = static fn (OwnerReference $owner): OwnershipSnapshot => new OwnershipSnapshot(
        OwnershipContextMode::Owner, $owner, ['kind' => 'actor', 'type' => 'user', 'id' => '1'],
    );
    $restore = $participant->enter($enter($first));
    try {
        expect($registrar->getPermissionsTeamId())->toBe($first->scopeKey());
        $inner = $participant->enter($enter($second));
        try {
            expect($registrar->getPermissionsTeamId())->toBe($second->scopeKey());
            throw new RuntimeException('consumer exception');
        } finally {
            $inner();
        }
    } catch (RuntimeException $exception) {
        expect($exception->getMessage())->toBe('consumer exception')
            ->and($registrar->getPermissionsTeamId())->toBe($first->scopeKey());
    } finally {
        $restore();
    }
    expect($registrar->getPermissionsTeamId())->toBe('previous-team');
});

it('uses distinct team identities for native key type and actual owner store', function (): void {
    $participant = app(AuthOwnerContextParticipant::class);
    $registrar = app(PermissionRegistrar::class);
    $seen = [];
    foreach ([['store-a', 'int'], ['store-a', 'string'], ['store-b', 'int']] as [$store, $type]) {
        $owner = new OwnerReference('company', $store, $type, '7');
        $restore = $participant->enter(new OwnershipSnapshot(OwnershipContextMode::Owner, $owner, ['kind' => 'actor', 'type' => 'user', 'id' => '1']));
        try {
            $seen[] = $registrar->getPermissionsTeamId();
        } finally {
            $restore();
        }
    }
    expect(array_unique($seen))->toHaveCount(3);
});
