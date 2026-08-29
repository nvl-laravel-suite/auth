<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Publishes one privacy-bounded invitation acceptance after storage commits.
 */
final class InvitationAccepted implements ShouldDispatchAfterCommit
{
    use Dispatchable;

    /**
     * Create the committed invitation acceptance event.
     */
    public function __construct(
        public readonly string $invitationId,
        public readonly string $type,
        public readonly string $purpose,
        public readonly SubjectReference $subject,
        public readonly ?CarbonImmutable $acceptedAt = null,
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
        ];

        if (isset($this->acceptedAt)) {
            $data['acceptedAt'] = $this->acceptedAt;
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
     *     acceptedAt?: CarbonImmutable|null
     * }  $data
     */
    public function __unserialize(array $data): void
    {
        $this->invitationId = $data['invitationId'];
        $this->type = $data['type'];
        $this->purpose = $data['purpose'];
        $this->subject = $data['subject'];
        $this->acceptedAt = $data['acceptedAt'] ?? null;
    }
}
