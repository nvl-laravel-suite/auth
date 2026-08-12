<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Nvl\Auth\Contracts\RoleTemplateProvider;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Data\Mutations\ApplyRoleTemplateData;
use Nvl\Auth\Data\Mutations\ConsumeMagicLinkData;
use Nvl\Auth\Data\Mutations\DeleteOwnAccountData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Data\Mutations\SyncUserPermissionsData;
use Nvl\Auth\Data\Mutations\SyncUserRolesData;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\ConfiguredPrincipalAttributeMapper;
use Nvl\Auth\Services\RoleTemplateRegistry;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;
use Nvl\Auth\ValueObjects\RoleTemplate;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Spatie\LaravelData\Optional;

it('exposes complete consumer validation rules and invitation registration data', function (): void {
    $registration = new AcceptInvitationData(
        token: 'token',
        name: 'Consumer',
        password: 'correct-password',
        passwordConfirmation: 'correct-password',
    );
    $socialRegistration = new AcceptInvitationData(
        token: 'token',
        name: 'Social Consumer',
        registrationMethod: 'social',
        password: new Optional,
        passwordConfirmation: new Optional,
    );

    expect($registration->toRegistrationArray())
        ->toMatchArray([
            'name' => 'Consumer',
            'password' => 'correct-password',
            'password_confirmation' => 'correct-password',
        ])
        ->and($socialRegistration->toRegistrationArray())->not->toHaveKeys([
            'password',
            'password_confirmation',
        ])
        ->and(AcceptInvitationData::rules())->toHaveKeys(['token', 'registrationMethod', 'password'])
        ->and(ConsumeMagicLinkData::rules())->toHaveKeys(['token', 'recipient', 'challengeId'])
        ->and(DeleteOwnAccountData::rules())->toHaveKey('currentPassword')
        ->and(ApplyRoleTemplateData::rules())->toHaveKeys(['template', 'roleName'])
        ->and(InvitationIndexQueryData::rules())->toHaveKeys([
            'recipient',
            'lifecycle',
            'expiresAfter',
            'expiresBefore',
            'perPage',
        ]);
});

it('rejects malformed role, invitation, and assignment consumer mutations', function (): void {
    $invalidMutations = [
        [static fn (): ApplyRoleTemplateData => new ApplyRoleTemplateData(''), 'Role template keys'],
        [static fn (): ApplyRoleTemplateData => new ApplyRoleTemplateData('member', ''), 'Target role names'],
        [static fn (): StoreInvitationData => new StoreInvitationData(''), 'Invitation recipients'],
        [static fn (): StoreInvitationData => new StoreInvitationData('user@example.test', type: ''), 'type or purpose'],
        [static fn (): StoreInvitationData => new StoreInvitationData('user@example.test', context: ''), 'Invitation contexts'],
        [static fn (): StoreInvitationData => new StoreInvitationData('user@example.test', roles: ['']), 'role and permission names'],
        [static fn (): StoreInvitationData => new StoreInvitationData('user@example.test', metadata: ['number' => NAN]), 'Invitation metadata'],
        [static fn (): SyncUserPermissionsData => new SyncUserPermissionsData(['read', 'read']), 'distinct list'],
        [static fn (): SyncUserPermissionsData => new SyncUserPermissionsData(['']), 'permission names'],
        [static fn (): SyncUserRolesData => new SyncUserRolesData(['admin', 'admin']), 'distinct list'],
        [static fn (): SyncUserRolesData => new SyncUserRolesData(['']), 'role names'],
    ];

    foreach ($invalidMutations as [$mutation, $message]) {
        expect($mutation)->toThrow(InvalidArgumentException::class, $message);
    }

    config()->set('nvl-auth.tables.permissions', 'consumer_permissions');
    config()->set('nvl-auth.tables.roles', 'consumer_roles');

    expect(new ApplyRoleTemplateData('member', 'consumer-member'))->toBeInstanceOf(ApplyRoleTemplateData::class)
        ->and(StoreInvitationData::rules())->toHaveKeys(['recipient', 'roles', 'permissions', 'metadata'])
        ->and(SyncUserPermissionsData::rules()['permissions.*'])->toContain('exists:consumer_permissions,name')
        ->and(SyncUserRolesData::rules()['roles.*'])->toContain('exists:consumer_roles,name');
});

it('validates and serializes role templates and system mutation contexts', function (): void {
    $template = new RoleTemplate(
        key: 'support-manager',
        permissions: ['tickets.read'],
        displayName: 'Support manager',
        description: 'Manages support requests.',
        priority: 50,
        metadata: ['surface' => 'support'],
    );
    $mutation = $template->toMutation('regional-support');
    $context = new SystemMutationContext(
        reason: 'Provision default access',
        correlationId: 'install-123',
        metadata: ['source' => 'installer'],
    );

    expect($mutation->name)->toBe('regional-support')
        ->and($template->toArray())->toMatchArray([
            'key' => 'support-manager',
            'roleName' => 'support-manager',
            'permissions' => ['tickets.read'],
        ])
        ->and($context->auditMetadata()['system'])->toBe([
            'reason' => 'Provision default access',
            'correlation_id' => 'install-123',
            'metadata' => ['source' => 'installer'],
        ]);

    $invalidTemplates = [
        static fn (): RoleTemplate => new RoleTemplate('', []),
        static fn (): RoleTemplate => new RoleTemplate('member', [], roleName: ''),
        static fn (): RoleTemplate => new RoleTemplate('member', [], description: str_repeat('a', 2_001)),
        static fn (): RoleTemplate => new RoleTemplate('member', [], priority: 100_001),
        static fn (): RoleTemplate => new RoleTemplate('member', ['read', 'read']),
        static fn (): RoleTemplate => new RoleTemplate('member', ['']),
        static fn (): RoleTemplate => new RoleTemplate('member', [], metadata: ['number' => NAN]),
        static fn (): RoleTemplate => new RoleTemplate('member', [], metadata: ['payload' => str_repeat('a', 65_536)]),
    ];

    foreach ($invalidTemplates as $invalidTemplate) {
        expect($invalidTemplate)->toThrow(InvalidArgumentException::class);
    }

    $invalidContexts = [
        static fn (): SystemMutationContext => new SystemMutationContext('', 'correlation'),
        static fn (): SystemMutationContext => new SystemMutationContext('Reason', ''),
        static fn (): SystemMutationContext => new SystemMutationContext('Reason', 'correlation', metadata: ['number' => NAN]),
        static fn (): SystemMutationContext => new SystemMutationContext('Reason', 'correlation', metadata: ['payload' => str_repeat('a', 65_536)]),
    ];

    foreach ($invalidContexts as $invalidContext) {
        expect($invalidContext)->toThrow(InvalidArgumentException::class);
    }
});

it('validates external identities and trusted invitation issuance policy', function (): void {
    expect(new ExternalIdentity(
        provider: 'github',
        providerUserId: 'provider-123',
        email: 'consumer@example.test',
        emailVerified: true,
        emailVerificationSource: 'provider-claim',
    ))->toBeInstanceOf(ExternalIdentity::class)
        ->and(new InvitationIssuanceContext(
            actorlessAuthorized: true,
            expiresAt: CarbonImmutable::now()->addDay(),
            returnPath: '/account/welcome',
        ))->toBeInstanceOf(InvitationIssuanceContext::class);

    $invalidValues = [
        static fn (): ExternalIdentity => new ExternalIdentity('Invalid Provider', 'provider-123'),
        static fn (): ExternalIdentity => new ExternalIdentity('github', 'provider-123', profile: ['number' => NAN]),
        static fn (): ExternalIdentity => new ExternalIdentity('github', 'provider-123', profile: ['payload' => str_repeat('a', 16_385)]),
        static fn (): ExternalIdentity => new ExternalIdentity('github', 'provider-123', emailVerified: true),
        static fn (): InvitationIssuanceContext => new InvitationIssuanceContext(expiresAt: CarbonImmutable::now()->subMinute()),
        static fn (): InvitationIssuanceContext => new InvitationIssuanceContext(expiresAt: CarbonImmutable::now()->addYear()->addDay()),
        static fn (): InvitationIssuanceContext => new InvitationIssuanceContext(returnPath: ''),
    ];

    foreach ($invalidValues as $invalidValue) {
        expect($invalidValue)->toThrow(InvalidArgumentException::class);
    }
});

it('normalizes configured principal fields and rejects unsafe mappings', function (): void {
    $configured = config('nvl-auth.features.principal_management.settings.attributes');
    $mapper = new ConfiguredPrincipalAttributeMapper;
    $mapped = $mapper->map([
        'name' => '  Consumer  ',
        'email' => '  CONSUMER@EXAMPLE.TEST  ',
        'locale' => ' bg ',
        'timezone' => ' Europe/Sofia ',
        'active' => false,
        'emailVerified' => true,
    ]);

    expect($mapper->identifierColumn('email'))->toBe('email')
        ->and($mapper->identifierColumn('external_reference'))->toBe('external_reference')
        ->and($mapper->column(PrincipalAttribute::Active))->toBe('is_active')
        ->and($mapped)->toMatchArray([
            'name' => 'Consumer',
            'email' => 'consumer@example.test',
            'locale' => 'bg',
            'timezone' => 'Europe/Sofia',
            'is_active' => false,
        ])
        ->and($mapped['email_verified_at'])->not->toBeNull()
        ->and($mapper->map(['emailVerified' => false])['email_verified_at'])->toBeNull();

    expect(static fn (): string => $mapper->identifierColumn('invalid identifier'))
        ->toThrow(AuthException::class, 'valid database identifier')
        ->and(static fn (): array => $mapper->map(['unknown' => 'value']))
        ->toThrow(AuthException::class, 'Unknown principal attribute');

    config()->set('nvl-auth.features.principal_management.settings.attributes', 'invalid');
    expect(static fn (): string => (new ConfiguredPrincipalAttributeMapper)->column(PrincipalAttribute::Id))
        ->toThrow(AuthException::class, 'must be an array');

    $invalidColumn = $configured;
    $invalidColumn['email'] = 'invalid column';
    config()->set('nvl-auth.features.principal_management.settings.attributes', $invalidColumn);
    expect(static fn (): string => (new ConfiguredPrincipalAttributeMapper)->column(PrincipalAttribute::Email))
        ->toThrow(AuthException::class, 'valid database identifier');

    $duplicateColumn = $configured;
    $duplicateColumn['email'] = $duplicateColumn['name'];
    config()->set('nvl-auth.features.principal_management.settings.attributes', $duplicateColumn);
    expect(static fn (): string => (new ConfiguredPrincipalAttributeMapper)->column(PrincipalAttribute::Email))
        ->toThrow(AuthException::class, 'distinct database columns');

    config()->set('nvl-auth.features.principal_management.settings.attributes', $configured);
    $principal = new User;
    $principal->setRawAttributes(['id' => []]);

    expect(static fn (): string => (new ConfiguredPrincipalAttributeMapper)->identifier($principal))
        ->toThrow(AuthException::class, 'string or integer');

    config()->set('nvl-auth.features.principal_management.settings.attributes', []);
    $defaults = new ConfiguredPrincipalAttributeMapper;

    expect($defaults->column(PrincipalAttribute::Id))->toBe('id')
        ->and($defaults->column(PrincipalAttribute::Active))->toBe('is_active');
});

it('sorts contributed role templates and rejects duplicate public keys', function (): void {
    $alpha = new RoleTemplate('alpha', []);
    $zulu = new RoleTemplate('zulu', []);
    $provider = new class([$zulu, $alpha]) implements RoleTemplateProvider
    {
        /** @param list<RoleTemplate> $templates */
        public function __construct(private readonly array $templates) {}

        /** @return list<RoleTemplate> */
        public function roles(): array
        {
            return $this->templates;
        }
    };

    expect(array_keys((new RoleTemplateRegistry([$provider]))->roles()))->toBe(['alpha', 'zulu']);

    $duplicateProvider = new class([$alpha]) implements RoleTemplateProvider
    {
        /** @param list<RoleTemplate> $templates */
        public function __construct(private readonly array $templates) {}

        /** @return list<RoleTemplate> */
        public function roles(): array
        {
            return $this->templates;
        }
    };

    expect(static fn (): array => (new RoleTemplateRegistry([$provider, $duplicateProvider]))->roles())
        ->toThrow(AuthException::class, 'must be unique');
});
