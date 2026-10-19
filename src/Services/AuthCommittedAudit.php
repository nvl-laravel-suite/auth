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

/** Captures native audit ownership while keeping host recorders after the source commit. */
final readonly class AuthCommittedAudit
{
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
    public function record(
        Connection $connection,
        string $action,
        string $outcome = 'success',
        ?SubjectReference $subject = null,
        ?Authenticatable $actor = null,
        ?string $clientId = null,
        array $metadata = [],
    ): void {
        if ($this->state->configured() && $this->recorder instanceof AuthAuditRecorder) {
            if ((new AuthAudit)->getConnection() !== $connection) {
                throw AuthException::invalidConfiguration('Native audit facts must share their owning source transaction.');
            }
            $this->recorder->record($action, $outcome, $subject, $actor, $clientId, $metadata);

            return;
        }
        $envelope = $this->state->configured() ? OwnershipJobEnvelope::capture($this->context) : null;
        $callback = $this->recorder instanceof AuthAuditRecorder
            ? $this->recorder->prepare($action, $outcome, $subject, $actor, $clientId, $metadata)
            : fn () => $this->recorder->record($action, $outcome, $subject, $actor, $clientId, $metadata);
        $this->commits->afterCommit($connection, function () use ($callback, $envelope): void {
            if ($envelope !== null) {
                $this->queue->run($envelope, $callback);

                return;
            }
            $callback();
        });
    }
}
