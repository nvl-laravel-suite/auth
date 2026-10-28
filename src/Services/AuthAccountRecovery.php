<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Contracts\AccountAuthenticationPolicy;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Events\AccountSecurityChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Support\Auth\CanonicalActorResolver;
use Nvl\Support\Events\DomainEventDispatcher;

/** Explicit support/system recovery with native containment and no identity/RBAC overrides. @api */
final readonly class AuthAccountRecovery
{
    public function __construct(private UserLocator $users, private MutationAuthorizer $authorization, private CanonicalActorResolver $canonical, private PrincipalSecurity $security, private UsableAccountAuthenticationPolicy $nativeRemoval, private AccountAuthenticationPolicy $policy, private PrincipalSessionContainment $containment, private FeatureGate $features, private AuthAuditRecorder $audits, private DomainEventDispatcher $events, private AuthAccountSecurity $inventory, private PrincipalAttributeMapper $attributes) {}

    /** @param array<string, mixed> $changes */
    public function recover(Authenticatable|SystemMutationContext $authority, User|string $subject, array $changes): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        if (array_diff(array_keys($changes), ['reason', 'correlationId', 'revokeSessions', 'revokeTokens', 'passkeyIds', 'socialIdentityIds', 'totpIds', 'revokeRecoveryCodes']) !== [] || ! is_string($changes['reason'] ?? null) || trim($changes['reason']) === '' || mb_strlen($changes['reason']) > 500) {
            throw new InvalidArgumentException('Recovery requires a bounded reason and closed containment instructions.');
        }
        $reason = trim($changes['reason']);
        $changes += ['correlationId' => (string) Str::uuid(), 'revokeSessions' => true, 'revokeTokens' => true, 'passkeyIds' => [], 'socialIdentityIds' => [], 'totpIds' => [], 'revokeRecoveryCodes' => true];
        if (! is_string($changes['correlationId']) || trim($changes['correlationId']) === '' || strlen($changes['correlationId']) > 160 || $changes['revokeSessions'] !== true || $changes['revokeTokens'] !== true || ! is_bool($changes['revokeRecoveryCodes'])) {
            throw new InvalidArgumentException('Recovery requires complete managed containment.');
        }
        $selection = ['passkey' => $this->identifiers($changes['passkeyIds']), 'social' => $this->identifiers($changes['socialIdentityIds']), 'totp' => $this->identifiers($changes['totpIds'])];
        $correlation = $changes['correlationId'];
        $user = $this->users->find($subject, true);
        $authority = $authority instanceof SystemMutationContext ? $authority : $this->canonical->resolve($authority);
        $this->authorization->authorize($authority, 'nvl.auth.users.recover', $user);

        return $user->getConnection()->transaction(function () use ($authority, $user, $changes, $selection, $reason, $correlation): User {
            $this->security->lock($user);
            $this->security->lockChallenges($user);
            $user = $this->users->find($user, true);
            $actor = $this->authorization->authorize($authority, 'nvl.auth.users.recover', $user);
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->security->assertTokenContainment($user);
            foreach (['passkeyIds' => [Passkey::class, 'passkey'], 'socialIdentityIds' => [SocialIdentity::class, 'social'], 'totpIds' => [TotpCredential::class, 'totp']] as $key => [$class, $kind]) {
                if ((new $class)->getConnection() !== $user->getConnection()) {
                    throw AuthException::invalidConfiguration('Recovery credential stores require one source.');
                }
                $ids = array_unique($selection[$kind]);
                sort($ids);
                foreach ($ids as $id) {
                    $record = $class::query()->whereKey($id)->lockForUpdate()->first();
                    if ($record === null || $record->subject_type !== $reference->type || $record->subject_id !== $reference->identifier) {
                        throw new AuthException('credential_unavailable', 'The recovery credential is unavailable.', 422);
                    }
                    if ($record->revoked_at !== null) {
                        continue;
                    }
                    $this->nativeRemoval->assertRemovalAllowed($user, $kind, $id);
                    $this->policy->assertRemovalAllowed($user, $kind, $id);
                    $this->nativeRemoval->assertRemovalAllowed($user, $kind, $id);
                    $record->update(['revoked_at' => now()]);
                }
            }
            if ($changes['revokeRecoveryCodes']) {
                $codes = new RecoveryCode;
                if ($codes->getConnection() !== $user->getConnection()) {
                    throw AuthException::invalidConfiguration('Recovery codes require one source.');
                }
                if ($codes->getConnection()->getSchemaBuilder()->hasTable($codes->getTable())) {
                    RecoveryCode::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->update(['revoked_at' => now()]);
                }
            }
            $state = $this->inventory->state($user);
            if ($this->attributes->value($user, PrincipalAttribute::Active) === true && ! $state['hasPassword'] && $state['passkeys'] === [] && $state['socialIdentities'] === [] && ! $this->inventory->hasEmailMethod($user)) {
                throw new AuthException('last_authentication_method', 'Recovery must preserve a usable primary method.', 422);
            }
            $this->security->advance($user, 'security_containment');
            $this->containment->contain($user, 'recovered', $authority instanceof SystemMutationContext ? $authority : null);
            $this->audits->record('account.recovered', subject: $reference, actor: $actor, metadata: [...$this->authorization->metadata($authority), 'reason' => $reason, 'correlation_id' => $correlation]);
            $this->events->dispatch(new AccountSecurityChanged($reference, 'account_recovered'), $user->getConnection());

            return $user->refresh();
        }, 3);
    }

    /** @return list<string> */
    private function identifiers(mixed $ids): array
    {
        if (! is_array($ids) || ! array_is_list($ids) || count($ids) > 100) {
            throw new InvalidArgumentException('Recovery selection must be a bounded list.');
        }
        $result = [];
        foreach ($ids as $id) {
            if (! is_string($id) || ! Str::isUuid($id)) {
                throw new InvalidArgumentException('Recovery credential identifiers must be UUIDs.');
            } $result[] = $id;
        }

        return $result;
    }
}
