<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Validator;
use InvalidArgumentException;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Contracts\TransactionalApiTokenManager;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use Nvl\Support\Events\DomainEventDispatcher;
use Throwable;

/**
 * Complete native AuthTokens operations.
 *
 * @api
 */
final readonly class AuthTokens
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private ApiTokenPolicy $policy, private ApiTokenManager $tokens, private AuthPipeline $pipeline, private AuthAuditRecorder $audits, private AuthCommittedAudit $committedAudits, private AuthenticationProofs $proofs, private SuccessfulLoginMetadataRecorder $loginMetadata, private DomainEventDispatcher $domainEvents, private ConnectionCommitCallbacks $commits) {}

    /** Complete stateless authentication from a native namespace-bound proof.
     * @param  array{name: string, abilities: list<string>, expiresAt?: CarbonImmutable|null}  $token
     * @return array{subject: Authenticatable, token: IssuedApiToken}
     */
    public function authenticateFromProof(#[\SensitiveParameter] string $proof, array $token, AuthenticationRequestContext $context): array
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Issue);
        try {
            $consumed = $this->proofs->consume($proof, AuthenticationDestination::ApiToken, $context);
        } catch (AuthException $exception) {
            $this->audits->record('authentication.rejected', outcome: 'failure', metadata: ['reason' => $exception->errorCode, 'stateless' => true]);
            $this->domainEvents->dispatch(new AuthenticationRejected('subject_reference', '', $exception->errorCode), (new AuthAudit)->getConnection());
            throw $exception;
        }
        $subject = $consumed['subject'];
        $evidence = $consumed['evidence'];
        $connection = $subject->getConnection();
        if ($this->connection($subject) !== $connection || (new AuthAudit)->getConnection() !== $connection) {
            throw AuthException::invalidConfiguration('Stateless authentication requires principal, token and audit writes on one connection.');
        }

        $sourceCommitted = false;
        try {
            return $connection->transaction(function () use ($evidence, $token, $context, $connection, &$sourceCommitted): array {
                $this->commits->afterCommit($connection, static function () use (&$sourceCommitted): void {
                    $sourceCommitted = true;
                });
                $principal = $this->proofs->recheck($evidence);
                $reference = $evidence->subject;
                $authenticated = $this->pipeline->run('login', new AuthPipelineContext('login', ['method' => $evidence->method->purpose()->value, 'stateless' => true], $reference), fn (): Authenticatable => $principal);
                if ($authenticated::class !== $principal::class || SubjectReference::fromAuthenticatable($authenticated) != $reference) {
                    throw new AuthException('login_rejected', 'The login pipeline changed the authenticated principal.', 422);
                }
                $principal = $this->proofs->recheck($evidence);
                $issued = $this->create($principal, $token);
                $principal = $this->proofs->recheck($evidence);
                $this->loginMetadata->record($principal, $context);
                $this->proofs->recheck($evidence);
                $this->committedAudits->withRecorder($this->audits)->record($connection, 'authentication.succeeded', subject: $reference, actor: $principal, metadata: ['method' => $evidence->method->purpose()->value, 'stateless' => true]);
                $this->domainEvents->dispatch(new UserAuthenticated($reference), $connection);

                return ['subject' => $principal, 'token' => $issued];
            });
        } catch (Throwable $exception) {
            if (! $sourceCommitted) {
                $reason = $exception instanceof AuthException ? $exception->errorCode : 'pipeline_rejected';
                $this->audits->record('authentication.rejected', outcome: 'failure', subject: $evidence->subject, actor: $subject, metadata: ['reason' => $reason, 'stateless' => true]);
                $this->domainEvents->dispatch(new AuthenticationRejected('subject_reference', $evidence->subject->identifier, $reason, $evidence->subject), $connection);
            }
            throw $exception;
        }
    }

    /** Require a token provider that can participate in complete authentication atomicity.
     *
     * @internal
     */
    public function connection(Authenticatable $subject): Connection
    {
        if (! $this->tokens instanceof TransactionalApiTokenManager) {
            throw AuthException::invalidConfiguration('Stateless login requires a TransactionalApiTokenManager.');
        }

        return $this->tokens->connection($subject);
    }

    /**
     * Issue one token directly through the configured provider.
     *
     * @param  array<string, mixed>  $data
     */
    public function create(Authenticatable $subject, array $data): IssuedApiToken
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Issue);
        $data = $this->validateApiToken($data);
        $subject = $this->policy->authorize($subject, $data);
        $reference = SubjectReference::fromAuthenticatable($subject);

        $issue = function () use ($data, $reference, $subject): IssuedApiToken {
            $subject = $this->policy->authorize($subject, $data);
            $issued = $this->pipeline->run('api_token_issued', new AuthPipelineContext('api_token_issued', ['abilities' => $data['abilities']], $reference), function () use ($data, $reference, $subject): IssuedApiToken {
                $subject = $this->policy->authorize($subject, $data);
                $issued = $this->tokens->create($subject, $data);
                $metadata = ['token_id' => $issued->token['id'], 'abilities' => $data['abilities']];
                if ($this->tokens instanceof TransactionalApiTokenManager) {
                    $this->committedAudits->withRecorder($this->audits)->record($this->tokens->connection($subject), 'api_token.issued', subject: $reference, actor: $subject, metadata: $metadata);
                } else {
                    $this->audits->record('api_token.issued', subject: $reference, actor: $subject, metadata: $metadata);
                }

                return $issued;
            });
            $this->policy->authorize($subject, $data);

            return $issued;
        };

        return $this->tokens instanceof TransactionalApiTokenManager ? $this->tokens->connection($subject)->transaction($issue) : $issue();
    }

    /**
     * Return subject-owned tokens.
     *
     * @return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}>
     */
    public function all(Authenticatable $subject): array
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Read);
        $subject = $this->policy->authorizeSubject($subject);

        return $this->tokens->list($subject);
    }

    /**
     * Revoke all tokens and return the affected count.
     */
    public function revokeAll(Authenticatable $subject): int
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Revoke);
        $subject = $this->policy->authorizeSubject($subject);
        $count = $this->tokens->revokeAll($subject);
        $this->audits->record('api_token.revoked_all', subject: SubjectReference::fromAuthenticatable($subject), actor: $subject, metadata: ['count' => $count]);

        return $count;
    }

    /**
     * Revoke one token idempotently.
     */
    public function revoke(Authenticatable $subject, string $tokenId): bool
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Revoke);
        $subject = $this->policy->authorizeSubject($subject);
        $revoked = $this->tokens->revoke($subject, $tokenId);
        if ($revoked) {
            $this->audits->record('api_token.revoked', subject: SubjectReference::fromAuthenticatable($subject), actor: $subject, metadata: ['token_id' => $tokenId]);
        }

        return $revoked;
    }

    /**
     * Rotate one token and return its replacement secret once.
     *
     * @param  array<string, mixed>  $data
     */
    public function rotate(Authenticatable $subject, string $tokenId, array $data): IssuedApiToken
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Update);
        $data = $this->validateApiToken($data);
        $subject = $this->policy->authorize($subject, $data);
        $issued = $this->tokens->rotate($subject, $tokenId, $data);
        $this->audits->record('api_token.rotated', subject: SubjectReference::fromAuthenticatable($subject), actor: $subject, metadata: ['old_token_id' => $tokenId, 'token_id' => $issued->token['id']]);

        return $issued;
    }

    /**
     * Update one subject-owned token.
     *
     * @param  array<string, mixed>  $data
     * @return array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}
     */
    public function update(Authenticatable $subject, string $tokenId, array $data): array
    {
        $this->features->assertAllowed(AuthFeature::ApiTokens, FeatureOperation::Update);
        $data = $this->validateApiToken($data);
        $subject = $this->policy->authorize($subject, $data);
        $updated = $this->tokens->update($subject, $tokenId, $data);
        $this->audits->record('api_token.updated', subject: SubjectReference::fromAuthenticatable($subject), actor: $subject, metadata: ['token_id' => $updated['id']]);

        return $updated;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}
     */
    private function validateApiToken(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'abilities', 'expiresAt']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['name'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [name].');
        }
        if (! is_array($data['abilities'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [abilities].');
        }
        if (! array_is_list($data['abilities'])) {
            throw new InvalidArgumentException('Auth input [abilities] must be a list.');
        }
        $data['abilities'] = array_map(static function (mixed $value): string {
            if (! is_string($value)) {
                throw new InvalidArgumentException('Auth input [abilities] must contain strings.');
            }

            return $value;
        }, $data['abilities']);
        if (! array_key_exists('expiresAt', $data)) {
            $data['expiresAt'] = null;
        }
        if (! ($data['expiresAt'] === null || $data['expiresAt'] instanceof CarbonImmutable)) {
            throw new InvalidArgumentException('Invalid Auth input [expiresAt].');
        }
        Validator::make($data, ['name' => ['required', 'string', 'max:120'], 'abilities' => ['required', 'array', 'min:1', 'max:100'], 'abilities.*' => ['required', 'string', 'max:120', 'distinct:strict'], 'expiresAt' => ['nullable', 'sometimes', 'nullable', 'date', 'after:now']])->validate();
        if (trim($data['name']) === '' || $data['name'] !== trim($data['name']) || mb_strlen($data['name']) > 120) {
            throw new InvalidArgumentException('API token name must contain between one and 120 characters.');
        }
        if ($data['abilities'] === []) {
            throw new InvalidArgumentException('API tokens require at least one ability.');
        }

        return $data;
    }
}
