<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\InvitationDeliveryStatus;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Support\Events\DomainEventDispatcher;
use Nvl\Support\Ownership\Contracts\OwnershipBoundary;
use Nvl\Support\Ownership\Contracts\OwnershipContext;

/**
 * Complete native AuthInvitations operations.
 *
 * @api
 */
final readonly class AuthInvitations
{
    private AuthCommittedAudit $committedAudits;

    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private AuthDeliveryContext $deliveryContext, private MutationAuthorizer $mutations, private OwnerInvitations $owned, private SecretHasher $hasher, private InvitationRecipientProof $recipientProof, private Container $container, private OwnershipBoundary $boundary, private OwnerMembershipAssignments $assignments, private ManagementAuthorizer $authorization, private AuthPipeline $pipeline, private AuthAuditRecorder $audits, AuthCommittedAudit $committedAudits, private DomainEventDispatcher $domainEvents, private OwnershipContext $ownerContext, private AuthConfiguration $configuration, private OpaqueTokenFactory $tokens, private AuthModelRegistry $models, private PasswordValidationRules $passwordPolicy, private InvitationPrincipalResolver $principalResolver, private ?InvitationDeliveryMetadataPolicy $deliveryMetadata = null)
    {
        $this->committedAudits = $committedAudits->withRecorder($this->audits);
    }

    /**
     * Consume an invitation for the supplied host subject.
     */
    public function accept(string $token, Authenticatable $subject): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Use);
        if (config('nvl-auth.ownership.scoped') === true) {
            return $this->owned->accept($token, $subject);
        }
        $reference = SubjectReference::fromAuthenticatable($subject);

        return $this->pipeline->run('invitation_accepted', new AuthPipelineContext('invitation_accepted', subject: $reference), function () use ($reference, $subject, $token): Invitation {
            $connection = (new Invitation)->getConnectionName();

            return DB::connection($connection)->transaction(function () use ($reference, $subject, $token): Invitation {
                /** @var Invitation|null $invitation */
                $invitation = Invitation::query()->where('token_hash', $this->hasher->hash('invitation-token', $token))->lockForUpdate()->first();
                if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
                    throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                }
                $this->recipientProof->assertMatches($invitation, $subject);
                $roles = is_array($invitation->roles) ? $invitation->roles : [];
                $permissions = is_array($invitation->permissions) ? $invitation->permissions : [];
                if ($roles !== [] || $permissions !== []) {
                    $this->container->make(RbacManager::class)->assign($subject, $roles, $permissions);
                }
                $acceptedAt = CarbonImmutable::now('UTC');
                $invitation->forceFill(['active_key' => null, 'accepted_by_type' => $reference->type, 'accepted_by_id' => $reference->identifier, 'accepted_at' => $acceptedAt])->save();
                $this->audits->record('invitation.accepted', subject: $reference, actor: $subject, metadata: ['invitation_id' => $invitation->identifier()]);
                $this->domainEvents->dispatch(new InvitationAccepted(invitationId: $invitation->identifier(), type: $invitation->type, purpose: $invitation->purpose, subject: $reference, acceptedAt: $invitation->accepted_at), $invitation->getConnection());

                return $invitation;
            }, 3);
        });
    }

    /**
     * Issue one invitation.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    public function create(#[\SensitiveParameter] array $data, Authenticatable|SystemMutationContext $authority, ?InvitationIssuanceContext $context = null): array
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Issue);
        $data = $this->validateStoreInvitation($data);
        $context ??= new InvitationIssuanceContext;
        $actor = $this->mutations->authorize($authority, 'nvl.auth.invitations.create');
        $ownership = $this->boundary->attributes('auth.invitations');
        $nativeOwner = config('nvl-auth.ownership.scoped') === true ? $this->ownerContext->requireOwner() : null;
        if ($nativeOwner !== null && ! $actor instanceof Authenticatable) {
            throw new AuthException('forbidden', 'Owned invitation issuance requires an authenticated issuer.', 403);
        }
        if ($data['roles'] !== [] || $data['permissions'] !== []) {
            $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        }
        $recipient = mb_strtolower(trim($data['recipient']));
        $recipientHash = $this->hasher->hash('invitation-recipient', $recipient);
        $ownershipKey = $nativeOwner?->scopeKey() ?? (is_string($ownership['ownership_key'] ?? null) ? $ownership['ownership_key'] : 'platform');
        $activeKey = $this->hasher->hash('active-invitation', $ownershipKey."\x00".$recipientHash."\x00".$data['purpose']);
        $grants = $nativeOwner === null ? ['roles' => $data['roles'], 'permissions' => $data['permissions']] : $this->assignments->canonicalIdentifiers($data['roles'], $data['permissions']);
        $actorReference = $actor instanceof Authenticatable ? SubjectReference::fromAuthenticatable($actor) : null;

        return $this->pipeline->run('invitation_issued', new AuthPipelineContext('invitation_issued', ['recipient_hash' => $recipientHash, 'purpose' => $data['purpose'], 'context' => $data['context']], $actorReference), function () use ($activeKey, $actor, $actorReference, $context, $data, $grants, $ownership, $recipient, $recipientHash): array {
            $connection = (new Invitation)->getConnectionName();
            try {
                return DB::connection($connection)->transaction(function () use ($actor, $activeKey, $actorReference, $data, $context, $connection, $recipient, $recipientHash, $grants, $ownership): array {
                    $this->boundary->query(Invitation::query(), 'auth.invitations')->where('active_key', $activeKey)->where('expires_at', '<=', CarbonImmutable::now('UTC'))->update(['active_key' => null]);
                    $duplicate = $this->boundary->query(Invitation::query(), 'auth.invitations')->where('active_key', $activeKey)->exists();
                    if ($duplicate) {
                        throw $this->createDuplicateInvitation();
                    }
                    $token = $this->tokens->make();
                    $messageId = (string) Str::uuid();
                    $expiresAt = $context->expiresAt ?? CarbonImmutable::now('UTC')->addHours($this->configuration->integerBetween('features.invitations.settings.ttl_hours', 72, 1, 8760));
                    $invitation = new Invitation(['token_hash' => $this->hasher->hash('invitation-token', $token), 'active_key' => $activeKey, 'recipient' => $recipient, 'recipient_hash' => $recipientHash, 'context_hash' => $data['context'] === null ? null : $this->hasher->hash('invitation-context', trim($data['context'])), 'type' => $data['type'], 'purpose' => $data['purpose'], 'inviter_type' => $actorReference?->type, 'inviter_id' => $actorReference?->identifier, 'roles' => $grants['roles'], 'permissions' => $grants['permissions'], 'metadata' => [...$data['metadata'], 'return_path' => $context->returnPath], 'resend_count' => 0, 'current_delivery_message_id' => $messageId, 'delivery_status' => InvitationDeliveryStatus::Pending, 'last_sent_at' => CarbonImmutable::now('UTC'), 'expires_at' => $expiresAt]);
                    $invitation->forceFill($ownership)->save();
                    $delivery = new AuthDeliveryRequest(messageId: $messageId, feature: AuthFeature::Invitations, type: AuthMessageType::Invitation, recipient: $recipient, payload: ['invitation_id' => $invitation->identifier(), 'token' => $token, 'type' => $data['type'], 'purpose' => $data['purpose'], 'return_path' => $context->returnPath], expiresAt: $expiresAt, locale: $data['locale'], metadata: ['invitation_id' => $invitation->identifier(), 'context' => $data['context']], invitation: ($this->deliveryMetadata ?? new InvitationDeliveryMetadataPolicy($this->configuration))->deliveryData($invitation));
                    $this->committedAudits->record(DB::connection($connection), 'invitation.issued', actor: $actor, metadata: ['invitation_id' => $invitation->identifier(), 'purpose' => $data['purpose']]);
                    $this->domainEvents->dispatch(new AuthDeliveryRequested($delivery, $this->deliveryContext->capture(false)), $invitation->getConnection());

                    return ['invitation' => $invitation, 'token' => $token];
                }, 3);
            } catch (QueryException $exception) {
                if (in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true) && (str_contains($exception->getMessage(), 'nvl_auth_invitations_active_key_unique') || str_contains($exception->getMessage(), 'auth_invitations.active_key'))) {
                    throw $this->createDuplicateInvitation($exception);
                }
                throw $exception;
            }
        });
    }

    /**
     * Build the stable active-invitation conflict.
     */
    private function createDuplicateInvitation(?QueryException $previous = null): AuthException
    {
        return new AuthException('invitation_exists', 'An active invitation already exists for this recipient and purpose.', 409, previous: $previous);
    }

    /**
     * Find the newest active invitation matching normalized trusted input.
     *
     * @param  list<string>|null  $types
     */
    public function findActive(string $recipient, string $purpose, ?array $types = null, ?string $context = null, Authenticatable|SystemMutationContext|null $authority = null): ?Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);
        if ($authority === null) {
            throw new AuthException('forbidden', 'Invitation lookup requires explicit authority.', 403);
        }
        $this->mutations->authorize($authority, 'nvl.auth.invitations.viewAny');
        $recipient = mb_strtolower(trim($recipient));
        $purpose = trim($purpose);
        $context = $context === null ? null : trim($context);
        if ($recipient === '' || mb_strlen($recipient) > 320) {
            throw new InvalidArgumentException('Invitation recipients must contain between one and 320 characters.');
        }
        if ($purpose === '' || mb_strlen($purpose) > 120) {
            throw new InvalidArgumentException('Invitation purposes must contain between one and 120 characters.');
        }
        if ($context !== null && ($context === '' || mb_strlen($context) > 191)) {
            throw new InvalidArgumentException('Invitation contexts must contain between one and 191 characters.');
        }
        $filters = $this->validateInvitationIndexQuery(['types' => $types]);
        $invitation = $this->boundary->query(Invitation::query(), 'auth.invitations')->where('recipient_hash', $this->hasher->hash('invitation-recipient', $recipient))->where('purpose', $purpose)->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '>', CarbonImmutable::now('UTC'))->when($filters['types'] !== null, fn ($query) => $query->whereIn('type', $filters['types']))->when($context !== null, fn ($query) => $query->where('context_hash', $this->hasher->hash('invitation-context', (string) $context)))->latest('created_at')->orderByDesc('id')->first();
        if (! $invitation instanceof Invitation) {
            return null;
        }

        return $invitation;
    }

    /**
     * Return a bounded invitation page.
     *
     * @param  array<string, mixed>  $filters
     * @return LengthAwarePaginator<int, Invitation>
     */
    public function paginate(Authenticatable $actor, array $filters = [], int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);
        $filters = $this->validateInvitationIndexQuery($filters);
        $this->authorization->authorize($actor, 'nvl.auth.invitations.viewAny');
        $query = $this->boundary->query(Invitation::query(), 'auth.invitations')->when($filters['recipient'] !== null, fn ($query) => $query->where('recipient_hash', $this->hasher->hash('invitation-recipient', mb_strtolower(trim((string) $filters['recipient'])))))->when($filters['type'] !== null, fn ($query) => $query->where('type', $filters['type']))->when($filters['types'] !== null, fn ($query) => $query->whereIn('type', $filters['types']))->when($filters['purpose'] !== null, fn ($query) => $query->where('purpose', $filters['purpose']))->when($filters['expiresAfter'] !== null, fn ($query) => $query->where('expires_at', '>=', CarbonImmutable::parse($filters['expiresAfter'])->utc()))->when($filters['expiresBefore'] !== null, fn ($query) => $query->where('expires_at', '<=', CarbonImmutable::parse($filters['expiresBefore'])->utc()))->when($filters['context'] !== null, fn ($query) => $query->where('context_hash', $this->hasher->hash('invitation-context', trim((string) $filters['context']))));
        match ($filters['lifecycle']) {
            'active' => $query->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '>', CarbonImmutable::now('UTC')),
            'accepted' => $query->whereNotNull('accepted_at'),
            'revoked' => $query->whereNotNull('revoked_at'),
            'expired' => $query->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '<=', CarbonImmutable::now('UTC')),
            default => null,
        };

        return $query->latest()->paginate($filters['per_page'] ?? max(1, min($perPage, 100)));
    }

    /**
     * Resolve one active invitation by its bearer token.
     */
    public function preview(string $token): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);
        if (config('nvl-auth.ownership.scoped') === true) {
            return $this->owned->preview($token);
        }
        /** @var Invitation|null $invitation */
        $invitation = Invitation::query()->where('token_hash', $this->hasher->hash('invitation-token', $token))->first();
        if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
            throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
        }

        return $invitation;
    }

    /**
     * Record a delivered or failed outcome idempotently.
     */
    public function recordDeliveryOutcome(string $invitationId, string $messageId, InvitationDeliveryStatus $status, CarbonImmutable $occurredAt, ?string $failureCode = null): void
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Update);
        $this->recordDeliveryOutcomeValidate($invitationId, $messageId, $status, $failureCode);
        $connection = (new Invitation)->getConnectionName();
        DB::connection($connection)->transaction(function () use ($failureCode, $invitationId, $messageId, $occurredAt, $status): void {
            /** @var Invitation|null $invitation */
            $invitation = $this->boundary->query(Invitation::query(), 'auth.invitations')->lockForUpdate()->find($invitationId);
            if (! $invitation instanceof Invitation) {
                throw new AuthException('invitation_unavailable', 'The invitation is unavailable.', 404);
            }
            if ($invitation->current_delivery_message_id !== $messageId) {
                $this->audits->record('invitation.delivery_outcome_stale', outcome: 'ignored', metadata: ['invitation_id' => $invitation->identifier(), 'message_id' => $messageId, 'current_message_id' => $invitation->current_delivery_message_id, 'delivery_status' => $status->value]);

                return;
            }
            if ($invitation->delivery_status === InvitationDeliveryStatus::Delivered || $invitation->delivery_status === $status) {
                return;
            }
            $attributes = ['delivery_status' => $status, 'delivery_attempted_at' => $occurredAt, 'delivered_at' => null, 'delivery_failed_at' => null, 'delivery_failure_code' => null];
            if ($status === InvitationDeliveryStatus::Delivered) {
                $attributes['delivered_at'] = $occurredAt;
            } else {
                $attributes['delivery_failed_at'] = $occurredAt;
                $attributes['delivery_failure_code'] = $failureCode;
            }
            $invitation->forceFill($attributes)->save();
            $this->audits->record('invitation.delivery_outcome_recorded', outcome: $status->value, metadata: ['invitation_id' => $invitation->identifier(), 'message_id' => $messageId]);
        }, 3);
    }

    /**
     * Validate bounded outcome input without accepting exception text.
     */
    private function recordDeliveryOutcomeValidate(string $invitationId, string $messageId, InvitationDeliveryStatus $status, ?string $failureCode): void
    {
        foreach ([$invitationId, $messageId] as $identifier) {
            if (trim($identifier) === '' || $identifier !== trim($identifier) || mb_strlen($identifier) > 191 || preg_match('/[\x00-\x1F\x7F]/', $identifier) === 1) {
                throw new InvalidArgumentException('Invitation outcome identifiers are invalid.');
            }
        }
        if ($status === InvitationDeliveryStatus::Pending) {
            throw new InvalidArgumentException('Invitation delivery outcomes must be Delivered or Failed.');
        }
        if ($status === InvitationDeliveryStatus::Failed && ($failureCode === null || preg_match('/\A[a-z0-9][a-z0-9_.-]{0,119}\z/', $failureCode) !== 1)) {
            throw new InvalidArgumentException('Failed invitation delivery outcomes require a safe failure code.');
        }
        if ($status === InvitationDeliveryStatus::Delivered && $failureCode !== null) {
            throw new InvalidArgumentException('A failure code is only valid for failed invitation delivery outcomes.');
        }
    }

    /** Register the invited subject and return the consumed invitation and subject.
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    public function register(#[\SensitiveParameter] array $data, ?Authenticatable $authenticatedRecipient = null): array
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Use);
        $data = $this->validateAcceptInvitation($data);
        if (config('nvl-auth.ownership.scoped') === true) {
            return $this->owned->register($data, $authenticatedRecipient);
        }

        return $this->registerRegister($data, $authenticatedRecipient);
    }

    /** Perform registration in the already-selected ownership boundary.
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    private function registerRegister(#[\SensitiveParameter] array $data, ?Authenticatable $authenticatedRecipient): array
    {
        $data = $this->validateAcceptInvitation($data);
        $connection = (new Invitation)->getConnectionName();
        $principalClass = $this->models->userClass();
        $principalConnection = (new $principalClass)->getConnection();
        if ($principalConnection !== (new Invitation)->getConnection()) {
            throw AuthException::invalidConfiguration('Invitation registration requires principal and invitation storage on one connection.');
        }
        try {
            $candidate = Invitation::query()->where('token_hash', $this->hasher->hash('invitation-token', $data['token']))->first();

            return DB::connection($connection)->transaction(function () use ($authenticatedRecipient, $connection, $data, $candidate): array {
                if ($candidate instanceof Invitation) {
                    $this->principalResolver->lockExisting($candidate);
                }
                $query = Invitation::query();
                /** @var Invitation|null $invitation */
                $invitation = $query->where('token_hash', $this->hasher->hash('invitation-token', $data['token']))->lockForUpdate()->first();
                if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
                    throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                }
                $subject = $this->registerResolveSubject($invitation, $data, $authenticatedRecipient);
                $reference = SubjectReference::fromAuthenticatable($subject);

                return $this->pipeline->run('invitation_accepted', new AuthPipelineContext('invitation_accepted', ['invitation_id' => $invitation->identifier(), 'type' => $invitation->type, 'purpose' => $invitation->purpose, 'metadata' => $invitation->metadata], $reference), function () use ($connection, $invitation, $reference, $subject): array {
                    $roles = is_array($invitation->roles) ? $invitation->roles : [];
                    $permissions = is_array($invitation->permissions) ? $invitation->permissions : [];
                    if ($roles !== [] || $permissions !== []) {
                        $this->container->make(RbacManager::class)->assign($subject, $roles, $permissions);
                    }
                    $acceptedAt = CarbonImmutable::now('UTC');
                    $invitation->forceFill(['active_key' => null, 'accepted_by_type' => $reference->type, 'accepted_by_id' => $reference->identifier, 'accepted_at' => $acceptedAt])->save();
                    $metadata = ['invitation_id' => $invitation->identifier()];
                    $this->committedAudits->record(DB::connection($connection), 'invitation.accepted', subject: $reference, actor: $subject, metadata: $metadata);
                    $this->domainEvents->dispatch(new InvitationAccepted(invitationId: $invitation->identifier(), type: $invitation->type, purpose: $invitation->purpose, subject: $reference, acceptedAt: $invitation->accepted_at, context: null), $invitation->getConnection());
                    $this->domainEvents->dispatch(new PrincipalChanged($reference->identifier, 'invitation_registered', context: null), $invitation->getConnection());

                    return ['invitation' => $invitation, 'subject' => $subject];
                });
            }, 3);
        } catch (QueryException $exception) {
            if (in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true)) {
                throw new AuthException('invitation_principal_conflict', 'The invited principal already exists.', 409, previous: $exception);
            }
            throw $exception;
        }
    }

    /** Resolve a new identity or require proof before reusing a global identity.
     * @param  array<string, mixed>  $data
     */
    private function registerResolveSubject(Invitation $invitation, #[\SensitiveParameter] array $data, ?Authenticatable $authenticatedRecipient): Authenticatable
    {
        return $this->principalResolver->resolve($invitation, $this->validateAcceptInvitation($data), $authenticatedRecipient);
    }

    /**
     * Resend one invitation with a newly rotated token.
     *
     * @return array<string, mixed>
     */
    public function resend(Invitation|string $invitation, Authenticatable|SystemMutationContext $authority, ?string $locale = null, ?InvitationIssuanceContext $context = null): array
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Issue);
        $context ??= new InvitationIssuanceContext;
        $identifier = $invitation instanceof Invitation ? $invitation->identifier() : $this->resendIdentifier($invitation);
        $connection = $invitation instanceof Invitation ? $invitation->getConnectionName() : (new Invitation)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($authority, $connection, $context, $identifier, $locale): array {
            /** @var Invitation $locked */
            $locked = $this->boundary->query(Invitation::query(), 'auth.invitations')->lockForUpdate()->findOrFail($identifier);
            $actor = $this->mutations->authorize($authority, 'nvl.auth.invitations.resend', $locked);
            if (! $locked->isUsable()) {
                throw new AuthException('invitation_unavailable', 'The invitation is no longer active.', 410);
            }
            $cooldown = $this->configuration->integerBetween('features.invitations.settings.resend_cooldown_seconds', 60, 1, 86400);
            if ($locked->last_sent_at?->addSeconds($cooldown)->isFuture()) {
                throw new AuthException('invitation_resend_limited', 'The invitation was sent too recently.', 429);
            }
            $token = $this->tokens->make();
            $messageId = (string) Str::uuid();
            $locked->forceFill(['token_hash' => $this->hasher->hash('invitation-token', $token), 'resend_count' => $locked->resend_count + 1, 'current_delivery_message_id' => $messageId, 'delivery_status' => InvitationDeliveryStatus::Pending, 'delivery_attempted_at' => null, 'delivered_at' => null, 'delivery_failed_at' => null, 'delivery_failure_code' => null, 'last_sent_at' => CarbonImmutable::now('UTC'), 'expires_at' => $context->expiresAt ?? $locked->expires_at])->save();
            $delivery = new AuthDeliveryRequest(messageId: $messageId, feature: AuthFeature::Invitations, type: AuthMessageType::Invitation, recipient: $locked->recipient, payload: ['invitation_id' => $locked->identifier(), 'token' => $token, 'type' => $locked->type, 'purpose' => $locked->purpose, 'return_path' => $context->returnPath ?? (is_array($locked->metadata) ? $locked->metadata['return_path'] ?? null : null)], expiresAt: $locked->expires_at, locale: $locale, metadata: ['invitation_id' => $locked->identifier(), 'resend' => true], invitation: ($this->deliveryMetadata ?? new InvitationDeliveryMetadataPolicy($this->configuration))->deliveryData($locked));
            $this->domainEvents->dispatch(new AuthDeliveryRequested($delivery, $this->deliveryContext->capture(false)), $locked->getConnection());
            $this->committedAudits->record(DB::connection($connection), 'invitation.resent', actor: $actor, metadata: ['invitation_id' => $locked->identifier()]);

            return ['invitation' => $locked, 'token' => $token];
        }, 3);
    }

    /**
     * Validate an invitation identifier supplied without a model instance.
     */
    private function resendIdentifier(string $identifier): string
    {
        if (trim($identifier) === '' || $identifier !== trim($identifier) || mb_strlen($identifier) > 191 || preg_match('/[\x00-\x1F\x7F]/', $identifier) === 1) {
            throw new InvalidArgumentException('Invitation identifiers are invalid.');
        }

        return $identifier;
    }

    /**
     * Revoke an invitation idempotently.
     */
    public function revoke(Invitation|string $invitation, Authenticatable $actor): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Revoke);
        $identifier = $invitation instanceof Invitation ? $invitation->identifier() : $this->revokeIdentifier($invitation);
        $connection = $invitation instanceof Invitation ? $invitation->getConnectionName() : (new Invitation)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $connection, $identifier): Invitation {
            /** @var Invitation $locked */
            $locked = $this->boundary->query(Invitation::query(), 'auth.invitations')->lockForUpdate()->findOrFail($identifier);
            $this->authorization->authorize($actor, 'nvl.auth.invitations.revoke', $locked);
            if ($locked->revoked_at === null && $locked->accepted_at === null) {
                $locked->forceFill(['active_key' => null, 'revoked_at' => CarbonImmutable::now('UTC')])->save();
                $this->committedAudits->record(DB::connection($connection), 'invitation.revoked', actor: $actor, metadata: ['invitation_id' => $locked->identifier()]);
            }

            return $locked;
        }, 3);
    }

    /**
     * Validate an invitation identifier supplied without a model instance.
     */
    private function revokeIdentifier(string $identifier): string
    {
        if (trim($identifier) === '' || $identifier !== trim($identifier) || mb_strlen($identifier) > 191 || preg_match('/[\x00-\x1F\x7F]/', $identifier) === 1) {
            throw new InvalidArgumentException('Invitation identifiers are invalid.');
        }

        return $identifier;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{token: string, name: string, registrationMethod: string, password?: string|null, passwordConfirmation?: string|null, locale: string|null, timezone: string|null, extensions: array<array-key, mixed>}
     */
    private function validateAcceptInvitation(#[\SensitiveParameter] array $data): array
    {
        if (array_diff(array_keys($data), ['token', 'name', 'registrationMethod', 'password', 'passwordConfirmation', 'locale', 'timezone', 'extensions']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['token'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [token].');
        }
        if (! is_string($data['name'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [name].');
        }
        if (! array_key_exists('registrationMethod', $data)) {
            $data['registrationMethod'] = 'password';
        }
        if (! is_string($data['registrationMethod'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [registrationMethod].');
        }
        if (! (! array_key_exists('password', $data) || ($data['password'] === null || is_string($data['password'])))) {
            throw new InvalidArgumentException('Invalid Auth input [password].');
        }
        if (! (! array_key_exists('passwordConfirmation', $data) || ($data['passwordConfirmation'] === null || is_string($data['passwordConfirmation'])))) {
            throw new InvalidArgumentException('Invalid Auth input [passwordConfirmation].');
        }
        if (! array_key_exists('locale', $data)) {
            $data['locale'] = null;
        }
        if (! ($data['locale'] === null || is_string($data['locale']))) {
            throw new InvalidArgumentException('Invalid Auth input [locale].');
        }
        if (! array_key_exists('timezone', $data)) {
            $data['timezone'] = null;
        }
        if (! ($data['timezone'] === null || is_string($data['timezone']))) {
            throw new InvalidArgumentException('Invalid Auth input [timezone].');
        }
        if (! array_key_exists('extensions', $data)) {
            $data['extensions'] = [];
        }
        if (! is_array($data['extensions'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [extensions].');
        }
        Validator::make($data, ['token' => ['required', 'string', 'max:128'], 'registrationMethod' => ['sometimes', 'in:password,social'], 'password' => ['nullable', 'required_unless:registrationMethod,social', 'nullable', 'string', 'confirmed:passwordConfirmation', ...$this->passwordPolicy->rules()], 'name' => ['required', 'string', 'max:160'], 'locale' => ['nullable', 'sometimes', 'nullable', 'string', 'max:12'], 'timezone' => ['nullable', 'sometimes', 'nullable', 'timezone:all'], 'extensions' => ['sometimes', 'array']])->validate();
        $validated = ['token' => $data['token'], 'name' => $data['name'], 'registrationMethod' => $data['registrationMethod'], 'locale' => $data['locale'], 'timezone' => $data['timezone'], 'extensions' => $data['extensions']];
        foreach (['password', 'passwordConfirmation'] as $field) {
            if (array_key_exists($field, $data)) {
                if ($data[$field] !== null && ! is_string($data[$field])) {
                    throw new InvalidArgumentException('Invalid invitation password input.');
                }
                $validated[$field] = $data[$field];
            }
        }

        return $validated;
    }

    /** Native Auth operation.
     * @param  array<array-key, mixed>  $grants
     *
     * @phpstan-assert list<string> $grants
     */
    private function validateStoreInvitationAssertGrantList(array $grants, int $maximum, string $field): void
    {
        if (! array_is_list($grants) || count($grants) > $maximum) {
            throw new InvalidArgumentException("Invitation {$field} must be a distinct list containing at most {$maximum} names.");
        }
        $seen = [];
        foreach ($grants as $grant) {
            if (! is_string($grant) || trim($grant) === '' || mb_strlen($grant) > 255) {
                throw new InvalidArgumentException('Invitation role and permission names must be non-empty strings no longer than 255 characters.');
            }
            if (isset($seen[$grant])) {
                throw new InvalidArgumentException("Invitation {$field} must be a distinct list containing at most {$maximum} names.");
            }
            $seen[$grant] = true;
        }
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{recipient: string, type: string, purpose: string, roles: list<string>, permissions: list<string>, metadata: array<array-key, mixed>, locale: string|null, context: string|null}
     */
    private function validateStoreInvitation(#[\SensitiveParameter] array $data): array
    {
        if (array_diff(array_keys($data), ['recipient', 'type', 'purpose', 'roles', 'permissions', 'metadata', 'locale', 'context']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['recipient'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [recipient].');
        }
        if (! array_key_exists('type', $data)) {
            $data['type'] = 'registration';
        }
        if (! is_string($data['type'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [type].');
        }
        if (! array_key_exists('purpose', $data)) {
            $data['purpose'] = 'registration';
        }
        if (! is_string($data['purpose'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [purpose].');
        }
        if (! array_key_exists('roles', $data)) {
            $data['roles'] = [];
        }
        if (! is_array($data['roles'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [roles].');
        }
        if (! array_key_exists('permissions', $data)) {
            $data['permissions'] = [];
        }
        if (! is_array($data['permissions'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [permissions].');
        }
        if (! array_key_exists('metadata', $data)) {
            $data['metadata'] = [];
        }
        if (! is_array($data['metadata'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [metadata].');
        }
        if (! array_key_exists('locale', $data)) {
            $data['locale'] = null;
        }
        if (! ($data['locale'] === null || is_string($data['locale']))) {
            throw new InvalidArgumentException('Invalid Auth input [locale].');
        }
        if (! array_key_exists('context', $data)) {
            $data['context'] = null;
        }
        if (! ($data['context'] === null || is_string($data['context']))) {
            throw new InvalidArgumentException('Invalid Auth input [context].');
        }
        if (trim($data['recipient']) === '' || mb_strlen($data['recipient']) > 320) {
            throw new InvalidArgumentException('Invitation recipients must contain between one and 320 characters.');
        }
        if (trim($data['type']) === '' || mb_strlen($data['type']) > 80 || trim($data['purpose']) === '' || mb_strlen($data['purpose']) > 120) {
            throw new InvalidArgumentException('Invitation type or purpose is invalid.');
        }
        if ($data['context'] !== null && (trim($data['context']) === '' || mb_strlen($data['context']) > 191)) {
            throw new InvalidArgumentException('Invitation contexts must contain between one and 191 characters.');
        }
        $this->validateStoreInvitationAssertGrantList($data['roles'], 100, 'roles');
        $this->validateStoreInvitationAssertGrantList($data['permissions'], 250, 'permissions');
        $encodedMetadata = json_encode($data['metadata']);
        if (! is_string($encodedMetadata) || strlen($encodedMetadata) > 16384) {
            throw new InvalidArgumentException('Invitation metadata must be JSON-serializable and no larger than 16 KiB.');
        }

        return $data;
    }

    /** Native Auth operation.
     * @param  array<array-key, mixed>|null  $types
     * @return list<string>|null
     */
    private static function validateInvitationIndexQueryNormalizeTypes(?array $types): ?array
    {
        if ($types === null || $types === []) {
            return null;
        }
        if (count($types) > 20 || ! array_is_list($types)) {
            throw new InvalidArgumentException('Invitation types must be a list containing at most 20 values.');
        }
        $normalized = [];
        foreach ($types as $type) {
            if (! is_string($type) || trim($type) === '' || mb_strlen($type) > 80) {
                throw new InvalidArgumentException('Invitation types must contain between one and 80 characters.');
            }
            $normalized[trim($type)] = true;
        }

        return array_keys($normalized);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{recipient: string|null, type: string|null, purpose: string|null, lifecycle: string|null, expiresAfter: string|null, expiresBefore: string|null, context: string|null, per_page: int|null, types: array<array-key, mixed>|null}
     */
    private function validateInvitationIndexQuery(#[\SensitiveParameter] array $data): array
    {
        if (array_diff(array_keys($data), ['recipient', 'type', 'purpose', 'lifecycle', 'expiresAfter', 'expiresBefore', 'context', 'per_page', 'types']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! array_key_exists('recipient', $data)) {
            $data['recipient'] = null;
        }
        if (! ($data['recipient'] === null || is_string($data['recipient']))) {
            throw new InvalidArgumentException('Invalid Auth input [recipient].');
        }
        if (! array_key_exists('type', $data)) {
            $data['type'] = null;
        }
        if (! ($data['type'] === null || is_string($data['type']))) {
            throw new InvalidArgumentException('Invalid Auth input [type].');
        }
        if (! array_key_exists('purpose', $data)) {
            $data['purpose'] = null;
        }
        if (! ($data['purpose'] === null || is_string($data['purpose']))) {
            throw new InvalidArgumentException('Invalid Auth input [purpose].');
        }
        if (! array_key_exists('lifecycle', $data)) {
            $data['lifecycle'] = null;
        }
        if (! ($data['lifecycle'] === null || is_string($data['lifecycle']))) {
            throw new InvalidArgumentException('Invalid Auth input [lifecycle].');
        }
        if (! array_key_exists('expiresAfter', $data)) {
            $data['expiresAfter'] = null;
        }
        if (! ($data['expiresAfter'] === null || is_string($data['expiresAfter']))) {
            throw new InvalidArgumentException('Invalid Auth input [expiresAfter].');
        }
        if (! array_key_exists('expiresBefore', $data)) {
            $data['expiresBefore'] = null;
        }
        if (! ($data['expiresBefore'] === null || is_string($data['expiresBefore']))) {
            throw new InvalidArgumentException('Invalid Auth input [expiresBefore].');
        }
        if (! array_key_exists('context', $data)) {
            $data['context'] = null;
        }
        if (! ($data['context'] === null || is_string($data['context']))) {
            throw new InvalidArgumentException('Invalid Auth input [context].');
        }
        if (! array_key_exists('per_page', $data)) {
            $data['per_page'] = null;
        }
        if (! ($data['per_page'] === null || is_int($data['per_page']))) {
            throw new InvalidArgumentException('Invalid Auth input [per_page].');
        }
        if (! array_key_exists('types', $data)) {
            $data['types'] = null;
        }
        if (! ($data['types'] === null || is_array($data['types']))) {
            throw new InvalidArgumentException('Invalid Auth input [types].');
        }
        $data['types'] = self::validateInvitationIndexQueryNormalizeTypes($data['types']);
        Validator::make($data, ['recipient' => ['nullable', 'sometimes', 'email:rfc', 'max:320'], 'type' => ['nullable', 'sometimes', 'string', 'max:80'], 'types' => ['nullable', 'sometimes', 'array', 'max:20'], 'types.*' => ['string', 'distinct', 'max:80'], 'purpose' => ['nullable', 'sometimes', 'string', 'max:120'], 'lifecycle' => ['nullable', 'sometimes', 'in:active,accepted,revoked,expired'], 'expiresAfter' => ['nullable', 'sometimes', 'date'], 'expiresBefore' => ['nullable', 'sometimes', 'date', 'after:expiresAfter'], 'context' => ['nullable', 'sometimes', 'string', 'max:191'], 'per_page' => ['nullable', 'sometimes', 'integer', 'between:1,100']])->validate();

        return $data;
    }
}
