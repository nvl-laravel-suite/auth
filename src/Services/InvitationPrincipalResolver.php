<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;

/** Validates a native invitation identity and records only in-operation Eloquent creation.
 * Host resolvers creating quietly/raw must supply authenticated recipient authority.
 * The exact prior dispatcher is restored even on failure or nested resolution.
 *
 * @internal
 */
final readonly class InvitationPrincipalResolver
{
    public function __construct(private AuthModelRegistry $models, private PrincipalAttributeMapper $attributes, private InvitationSubjectResolver $subjects, private InvitationRecipientProof $proof, private CanonicalActorResolver $canonical, private PrincipalSecurity $security, private ConfiguredRegistrationAdmission $registration) {}

    /** Lock a known recipient before an invitation/delegation row; never gap-lock an absent mailbox. */
    public function lockExisting(Invitation $invitation): void
    {
        $class = $this->models->userClass();
        PrincipalEmailIdentity::assertReady(new $class);
        if ((new $class)->getConnection() !== $invitation->getConnection()) {
            throw AuthException::invalidConfiguration('Invitation and canonical principal must share their actual source.');
        }
        $existing = $class::query()->withTrashed()->where($this->attributes->column(PrincipalAttribute::EmailIdentityHash), PrincipalEmailIdentity::key($invitation->recipient))->first();
        if ($existing !== null) {
            $this->security->lock($existing);
        }
    }

    /** Resolve on the invitation transaction without treating cached model flags as authority.
     * @param  array<string, mixed>  $data
     */
    public function resolve(Invitation $invitation, #[\SensitiveParameter] array $data, ?Authenticatable $authenticated): Authenticatable
    {
        $class = $this->models->userClass();
        PrincipalEmailIdentity::assertReady(new $class);
        $prototype = new $class;
        if ($prototype->getConnection() !== $invitation->getConnection()) {
            throw AuthException::invalidConfiguration('Invitation and canonical principal must share their actual source.');
        }
        $email = $this->attributes->column(PrincipalAttribute::Email);
        $recipient = PrincipalEmailIdentity::normalize($invitation->recipient);
        $existing = $class::query()->withTrashed()->where($this->attributes->column(PrincipalAttribute::EmailIdentityHash), PrincipalEmailIdentity::key($recipient))->first();
        if ($existing !== null && $existing->trashed()) {
            throw new AuthException('invitation_principal_conflict', 'The invited identity is unavailable.', 409);
        }
        if ($existing !== null) {
            $this->security->lock($existing);
            $this->assertRecipient($invitation, $existing, $authenticated);

            return $existing;
        }
        if (($data['registrationMethod'] ?? 'password') !== 'password') {
            throw new AuthException('social_registration_unavailable', 'Verified social registration is not available yet.', 422);
        }
        $this->registration->assertProvisioningAllowed(invited: true);
        $dispatcher = Model::getEventDispatcher();
        if ($dispatcher === null) {
            throw AuthException::invalidConfiguration('Invitation provisioning requires Eloquent creation events.');
        }
        $receipt = new InvitationCreationReceipt($dispatcher, $prototype);
        try {
            Model::setEventDispatcher($receipt);
            $subject = $this->subjects->resolve($invitation, array_diff_key($data, ['token' => true]) + ['password_confirmation' => $data['passwordConfirmation'] ?? null]);
        } finally {
            Model::setEventDispatcher($dispatcher);
        }
        if (! $subject instanceof Model || $subject::class !== $class || ! $subject->exists
            || $subject->getConnection() !== $prototype->getConnection() || $subject->getTable() !== $prototype->getTable()
            || $subject->getKeyName() !== $prototype->getKeyName() || $subject->isDirty($prototype->getKeyName())) {
            throw AuthException::invalidConfiguration('The invitation resolver must persist the canonical invited identity on the same source.');
        }
        $fresh = $class::query()->useWritePdo()->whereKey($subject->getKey())->first();
        if ($fresh === null || $fresh->getAttribute($fresh->getEmailIdentityHashName()) !== PrincipalEmailIdentity::key($recipient) || ! is_string($fresh->getAttribute($email)) || PrincipalEmailIdentity::normalize($fresh->getAttribute($email)) !== $recipient) {
            throw AuthException::invalidConfiguration('The invitation resolver must persist the canonical invited recipient.');
        }
        if (! $receipt->contains($fresh)) {
            $this->assertRecipient($invitation, $fresh, $authenticated);
        }
        $this->security->lock($fresh);

        return $fresh;
    }

    /** Require canonical authenticated recipient proof when reusing a persisted account. */
    private function assertRecipient(Invitation $invitation, Authenticatable $subject, ?Authenticatable $authenticated): void
    {
        if ($authenticated === null) {
            throw $this->proofRequired();
        }
        $authenticated = $this->canonical->resolve($authenticated);
        if ($authenticated::class !== $subject::class || SubjectReference::fromAuthenticatable($subject) != SubjectReference::fromAuthenticatable($authenticated)) {
            throw $this->proofRequired();
        }
        $this->proof->assertMatches($invitation, $authenticated);
    }

    private function proofRequired(): AuthException
    {
        return new AuthException('invitation_identity_proof_required', 'The invitation recipient identity could not be verified.', 403);
    }
}
