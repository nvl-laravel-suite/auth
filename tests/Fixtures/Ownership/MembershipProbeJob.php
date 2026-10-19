<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Ownership;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Contracts\OwnershipQueuedJob;
use Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope;

/** Records restoration and execution only after the real worker has re-admitted the actor. */
final class MembershipProbeJob implements OwnershipQueuedJob, ShouldQueue
{
    public int $tries = 1;

    /** Retain identifiers and producer capture without serialized Eloquent records. */
    public function __construct(public OwnershipJobEnvelope $ownership, public string $membershipId, public string $label) {}

    /** Return the original producer's captured scope. */
    public function ownershipJobEnvelope(): OwnershipJobEnvelope
    {
        return $this->ownership;
    }

    /** @return array{ownership: OwnershipJobEnvelope, membershipId: string, label: string} */
    public function __serialize(): array
    {
        return ['ownership' => $this->ownership, 'membershipId' => $this->membershipId, 'label' => $this->label];
    }

    /** @param array{ownership: OwnershipJobEnvelope, membershipId: string, label: string} $values */
    public function __unserialize(array $values): void
    {
        $this->ownership = $values['ownership'];
        $this->membershipId = $values['membershipId'];
        $this->label = $values['label'];
        self::observe('auth-restore', $this->label);
    }

    /** Resolve the canonical membership inside the freshly authorized native scope. */
    public function handle(): void
    {
        OwnerMembership::query()->findOrFail($this->membershipId);
        self::observe('auth-handle', $this->label);
    }

    /** Record only the worker's actual execution scope. */
    private static function observe(string $stage, string $label): void
    {
        DB::table('ownership_queue_probes')->insert(['stage' => $stage, 'owner' => app(OwnershipContext::class)->requireOwner()->key, 'label' => $label]);
    }
}
