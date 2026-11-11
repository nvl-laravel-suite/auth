<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Nvl\Auth\Contracts\AuthAuditRecorder as RecorderContract;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Contracts\OwnershipQueueContext;
use Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope;

/**
 * Captures native audit ownership while keeping host recorders after the source commit.
 *
 * @internal
 */
final readonly class AuthCommittedAudit
{
    /** Create the after-commit audit recorder. */
    public function __construct(private RecorderContract $recorder, private ConnectionCommitCallbacks $commits, private AuthOwnershipState $state, private OwnershipContext $context, private OwnershipQueueContext $queue) {}

    /**
     * Retain the source connection callbacks while selecting the caller's recorder.
     *
     * @internal
     */
    public function withRecorder(RecorderContract $recorder): self
    {
        return new self($recorder, $this->commits, $this->state, $this->context, $this->queue);
    }

    /** @param array<string, mixed> $metadata */
    public function record(Connection $connection, string $action, string $outcome = 'success', ?SubjectReference $subject = null, ?Authenticatable $actor = null, ?string $clientId = null, array $metadata = []): void
    {
        if ($this->recorder instanceof AuthAuditRecorder) {
            if ((new AuthAudit)->getConnection() !== $connection) {
                throw AuthException::invalidConfiguration('Native audit facts must share their owning source transaction.');
            }
            $this->recorder->record($action, $outcome, $subject, $actor, $clientId, $metadata);

            return;
        }
        $envelope = $this->state->configured() ? OwnershipJobEnvelope::capture($this->context) : null;
        $callback = fn () => $this->recorder->record($action, $outcome, $subject, $actor, $clientId, $metadata);
        $this->commits->afterCommit($connection, function () use ($callback, $envelope): void {
            if ($envelope !== null) {
                $this->queue->run($envelope, $callback);

                return;
            }
            $callback();
        });
    }

    /**
     * Capture synchronization context while recording success after its actual source commit.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function afterCommit(Connection $connection, string $action, ?Authenticatable $actor = null, array $metadata = []): void
    {
        if (! $this->recorder instanceof AuthAuditRecorder) {
            $this->record($connection, $action, actor: $actor, metadata: $metadata);

            return;
        }

        $callback = $this->recorder->prepare($action, actor: $actor, metadata: $metadata);
        $this->commits->afterCommit($connection, static function () use ($callback): void {
            $callback();
        });
    }
}
