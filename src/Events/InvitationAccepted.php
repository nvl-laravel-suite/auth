<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Carbon\CarbonImmutable;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Contracts\DomainEvent;
use ReflectionProperty;

/**
 * Publishes one privacy-bounded invitation acceptance after storage commits.
 *
 * @api
 */
final class InvitationAccepted implements DomainEvent
{
    /**
     * Create the committed invitation acceptance event.
     */
    public function __construct(
        public readonly string $invitationId,
        public readonly string $type,
        public readonly string $purpose,
        public readonly SubjectReference $subject,
        public readonly ?CarbonImmutable $acceptedAt = null,
        public readonly ?AuthEventContext $context = null,
        public readonly int $schemaVersion = 1,
    ) {}

    /**
     * Serialize initialized acceptance fields, including legacy-shaped instances.
     *
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        $data = [
            'invitationId' => $this->invitationId,
            'type' => $this->type,
            'purpose' => $this->purpose,
            'subject' => $this->subject,
            'schemaVersion' => (new ReflectionProperty($this, 'schemaVersion'))->isInitialized($this) ? $this->schemaVersion : 1,
        ];

        if (isset($this->acceptedAt)) {
            $data['acceptedAt'] = $this->acceptedAt;
        }

        if (isset($this->context)) {
            $data['context'] = $this->context;
        }

        return $data;
    }

    /**
     * Restore the timestamp omitted by events queued before it existed.
     *
     * @param  array{
     *     invitationId: string,
     *     type: string,
     *     purpose: string,
     *     subject: SubjectReference,
     *     acceptedAt?: CarbonImmutable|null,
     *     context?: AuthEventContext|null,
     *     schemaVersion?: int
     * }  $data
     */
    public function __unserialize(array $data): void
    {
        $this->invitationId = $data['invitationId'];
        $this->type = $data['type'];
        $this->purpose = $data['purpose'];
        $this->subject = $data['subject'];
        $this->acceptedAt = $data['acceptedAt'] ?? null;
        $this->context = $data['context'] ?? null;
        $this->schemaVersion = $data['schemaVersion'] ?? 1;
    }

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}
