<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Support\Ownership\Contracts\OwnershipBoundary;

/**
 * Complete native AuthAuditReader operations.
 *
 * @api
 */
final readonly class AuthAuditReader
{
    /** Create the authorized audit trail reader. */
    public function __construct(private FeatureGate $features, private ManagementAuthorizer $authorization, private OwnershipBoundary $boundary) {}

    /**
     * Return a bounded audit page.
     *
     * @return LengthAwarePaginator<int, AuthAudit>
     */
    public function paginate(Authenticatable $actor, int $perPage = 50): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Audit, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.audits.viewAny');

        return $this->boundary->query(AuthAudit::query(), 'auth.audits')->latest()->paginate(max(1, min($perPage, 100)));
    }

    /**
     * Authorize and return one route-resolved audit.
     */
    public function find(Authenticatable $actor, AuthAudit $audit): AuthAudit
    {
        $this->features->assertAllowed(AuthFeature::Audit, FeatureOperation::Read);
        /** @var AuthAudit $record */
        $record = $this->boundary->query(AuthAudit::query(), 'auth.audits')->whereKey($audit->getKey())->firstOrFail();
        $this->authorization->authorize($actor, 'nvl.auth.audits.view', $record);

        return $record;
    }
}
