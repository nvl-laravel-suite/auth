<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Nvl\Auth\Contracts\AuthAuditRecorder as RecorderContract;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;

/** Captures native audit ownership while keeping host recorders after the source commit. */
final readonly class AuthCommittedAudit
{
    public function __construct(private RecorderContract $recorder, private ConnectionCommitCallbacks $commits) {}

    /**
     * Retain the source connection callbacks while selecting the caller's recorder.
     *
     * @internal
     */
    public function withRecorder(RecorderContract $recorder): self
    {
        return new self($recorder, $this->commits);
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
        $callback = $this->recorder instanceof AuthAuditRecorder
            ? $this->recorder->prepare($action, $outcome, $subject, $actor, $clientId, $metadata)
            : fn () => $this->recorder->record($action, $outcome, $subject, $actor, $clientId, $metadata);
        $this->commits->afterCommit($connection, static function () use ($callback): void {
            $callback();
        });
    }
}
