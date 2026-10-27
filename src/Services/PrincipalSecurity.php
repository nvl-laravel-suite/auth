<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletingScope;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\SecurityTokenContainment;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\PrincipalSecurityState;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Serializes native credential mutations on the principal's actual source.
 * Lock principals/states and native challenges before credentials; advance on successful mutation.
 * Revisions are never pruned or reset, including soft deletion and restoration.
 *
 * @internal
 */
final readonly class PrincipalSecurity
{
    public function __construct(private AuthConfiguration $configuration, private ApiTokenManager $tokens) {}

    /** @var list<string> */
    private const REASONS = ['password_reset', 'password_changed', 'password_admin_reset', 'totp_pending_replaced', 'totp_enrolled', 'totp_revoked', 'recovery_replaced', 'recovery_revoked', 'passkey_enrolled', 'passkey_revoked', 'social_linked', 'social_revoked', 'principal_disabled', 'principal_enabled', 'principal_deleted', 'principal_restored', 'email_changed', 'security_containment'];

    /** Lock the canonical principal followed by its retained security state. */
    public function lock(Authenticatable $subject): PrincipalSecurityState
    {
        $principal = $this->principal($subject);
        $connection = $principal->getConnection();
        if ($connection->transactionLevel() === 0) {
            throw new \LogicException('Security locks require the owning source transaction.');
        }
        $principal->newQuery()->withoutGlobalScope(SoftDeletingScope::class)->useWritePdo()->whereKey($principal->getKey())->lockForUpdate()->firstOrFail();
        $reference = SubjectReference::fromAuthenticatable($principal);
        $query = PrincipalSecurityState::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->lockForUpdate();
        $state = $query->first();
        if ($state === null) {
            try {
                $state = $connection->transaction(fn (): PrincipalSecurityState => PrincipalSecurityState::query()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'revision' => 1]));
            } catch (UniqueConstraintViolationException $exception) {
                $state = $query->first() ?? throw $exception;
            }
        }

        return $state;
    }

    /** Lock native capabilities after all participating principals and states, before credentials. */
    public function lockChallenges(Authenticatable $subject): void
    {
        $principal = $this->principal($subject);
        if ($principal->getConnection()->transactionLevel() === 0) {
            throw new \LogicException('Challenge locks require the owning source transaction.');
        }
        if ($principal->getConnection()->getSchemaBuilder()->hasTable((new Challenge)->getTable())) {
            $this->challenges(SubjectReference::fromAuthenticatable($principal))->orderBy('id')->lockForUpdate()->get();
        }
    }

    /** Read or initialize the current monotonic security revision. */
    public function revision(Authenticatable $subject): int
    {
        return $this->principal($subject)->getConnection()->transaction(fn (): int => $this->lock($subject)->revision, 3);
    }

    /** Read a nonlocking revision snapshot without creating state, even in a host transaction.
     * Revalidate this value under lock before accepting provider verification.
     */
    public function revisionSnapshot(Authenticatable $subject): int
    {
        $reference = SubjectReference::fromAuthenticatable($this->principal($subject, lock: false));
        $state = PrincipalSecurityState::query()->useWritePdo()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->first();

        return $state->revision ?? 1;
    }

    /** Advance inside the owning transaction; rollback restores every invalidation. */
    public function advance(Authenticatable $subject, string $reason): int
    {
        if (! in_array($reason, self::REASONS, true)) {
            throw new InvalidArgumentException('Unknown native security revision reason.');
        }
        $passwordChange = in_array($reason, ['password_reset', 'password_changed', 'password_admin_reset'], true);
        if ($passwordChange) {
            $this->assertTokenContainment($subject);
        }
        $state = $this->lock($subject);
        $this->lockChallenges($subject);
        $state->increment('revision');
        $principal = $this->principal($subject);
        if ($principal->getConnection()->getSchemaBuilder()->hasTable((new Challenge)->getTable())) {
            $this->challenges(SubjectReference::fromAuthenticatable($principal))->update(['revoked_at' => now(), 'active_key' => null]);
        }
        if ($principal->getRememberTokenName() !== '') {
            $principal->setRememberToken(Str::random(60));
            $principal->saveQuietly();
        }
        if ($passwordChange && $this->configuration->featureEnabled(AuthFeature::ApiTokens)) {
            $this->tokenContainment()->revokeForSecurity($principal);
        }

        return $state->revision;
    }

    /** Validate the selected security containment adapter before credential or state writes. */
    public function assertTokenContainment(Authenticatable $subject): void
    {
        if (! $this->configuration->featureEnabled(AuthFeature::ApiTokens)) {
            return;
        }
        $principal = $this->principal($subject);
        if ($this->tokenContainment()->connection($principal) !== $principal->getConnection()) {
            throw AuthException::invalidConfiguration('Security token containment must share the actual principal source.');
        }
    }

    /** Resolve the host-selected adapter only when API tokens are enabled. */
    private function tokenContainment(): SecurityTokenContainment
    {
        $tokens = $this->tokens;
        if (! $tokens instanceof SecurityTokenContainment) {
            throw AuthException::invalidConfiguration('Enabled API tokens require SecurityTokenContainment for credential mutations.');
        }

        return $tokens;
    }

    /** Require persisted canonical storage, retaining soft-deleted principal identity. */
    private function principal(Authenticatable $subject, bool $lock = true): Model&Authenticatable
    {
        if (! $subject instanceof Model || ! $subject->exists) {
            throw AuthException::invalidConfiguration('Security state requires a persisted Eloquent principal.');
        }
        $prototype = new ($subject::class);
        if ($subject->getTable() !== $prototype->getTable()
            || $subject->getConnection() !== $prototype->getConnection()
            || $subject->getKeyName() !== $prototype->getKeyName() || $subject->getKeyType() !== $prototype->getKeyType()
            || $subject->isDirty($prototype->getKeyName()) || $subject->getKey() === null
            || $prototype->getConnection() !== (new PrincipalSecurityState)->getConnection()) {
            throw AuthException::invalidConfiguration('Principal and security state require canonical storage on the same actual connection.');
        }
        $query = $prototype->newQuery()->withoutGlobalScope(SoftDeletingScope::class)->useWritePdo()->whereKey($subject->getRawOriginal($prototype->getKeyName()));
        if ($lock && $prototype->getConnection()->transactionLevel() > 0) {
            $query->lockForUpdate();
        }
        $fresh = $query->first();
        if (! $fresh instanceof Authenticatable) {
            throw AuthException::invalidConfiguration('The canonical security principal is unavailable.');
        }

        return $fresh;
    }

    /** Only native authentication capabilities are invalidated; business challenges remain intact.
     */
    private function challenges(SubjectReference $subject): Builder
    {
        $model = new Challenge;

        return $model->getConnection()->table($model->getTable())->where('subject_type', $subject->type)->where('subject_id', $subject->identifier)
            ->whereIn('type', ['passkey_authentication', 'passkey_registration', 'credential_second_factor', 'authentication_proof', 'native_email_link', 'native_email_code'])
            ->whereNull('consumed_at')->whereNull('revoked_at');
    }
}
