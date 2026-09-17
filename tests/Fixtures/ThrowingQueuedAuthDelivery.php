<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Tenancy\Contracts\TenantContext;
use RuntimeException;

/** Fails its first durable attempt so a real worker retry proves context cleanup. */
final class ThrowingQueuedAuthDelivery implements ShouldQueue
{
    public int $tries = 2;

    public function __construct(private TenantContext $context) {}

    public function shouldQueue(AuthDeliveryRequested $event): bool
    {
        return $event->request->messageId === 'delivery-a';
    }

    public function handle(AuthDeliveryRequested $event): void
    {
        $tenant = $this->context->requireTenant()->value;
        $attempt = DB::table('nvl_auth_test_delivery_receipts')
            ->where('tenant_id', $tenant)
            ->where('message_id', $event->request->messageId)
            ->where('attempt', '>=', 10)
            ->max('attempt');
        $next = is_numeric($attempt) ? (int) $attempt + 1 : 10;
        DB::table('nvl_auth_test_delivery_receipts')->insert([
            'tenant_id' => $tenant,
            'message_id' => $event->request->messageId,
            'attempt' => $next,
        ]);
        if ($next === 10) {
            throw new RuntimeException('Expected first queued delivery attempt failure.');
        }
    }
}
