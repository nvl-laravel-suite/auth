<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Audit;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Tenancy\Services\TenantBoundary;

/**
 * Lists simple package audit records.
 */
final readonly class ListAuthAuditsAction
{
    /**
     * Create the audit listing use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private TenantBoundary $boundary,
    ) {}

    /**
     * Return a bounded audit page.
     *
     * @return LengthAwarePaginator<int, AuthAudit>
     */
    public function execute(Authenticatable $actor, int $perPage = 50): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Audit, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.audits.viewAny');

        return $this->boundary->query(AuthAudit::query(), 'auth.audits')
            ->latest()->paginate(max(1, min($perPage, 100)));
    }
}
