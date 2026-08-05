<?php

declare(strict_types=1);

use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Models\AuthClientSession;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Models\User;

it('provides a working factory for every package-owned model', function (): void {
    $models = [
        User::factory()->create(),
        Role::factory()->create(),
        Permission::factory()->create(),
        PersonalAccessToken::factory()->create(),
        AuthClient::factory()->create(),
        AuthClientSession::factory()->create(['metadata' => ['source' => 'test']]),
        Invitation::factory()->create(),
        Challenge::factory()->create(),
        TotpCredential::factory()->create(),
        Passkey::factory()->create(),
        RecoveryCode::factory()->create(),
        SocialIdentity::factory()->create(),
        AuthAudit::factory()->create(),
    ];

    foreach ($models as $model) {
        expect((string) $model->getKey())->not->toBeEmpty();
    }

    expect((string) $models[5]->getRawOriginal('metadata'))->not->toContain('source');
});
