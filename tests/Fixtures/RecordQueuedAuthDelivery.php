<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Support\Ownership\Contracts\OwnershipContext;

/** Records only scalar worker evidence in the test-owned receipt table. */
final readonly class RecordQueuedAuthDelivery implements ShouldQueue
{
    public function __construct(private OwnershipContext $context) {}

    public function handle(AuthDeliveryRequested $event): void
    {
        DB::table('nvl_auth_test_delivery_receipts')->insert([
            'owner_key' => $this->context->requireOwner()->key,
            'message_id' => $event->request->messageId,
            'attempt' => 1,
        ]);
    }
}
