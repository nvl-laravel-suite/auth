<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Audit;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Tenancy\Services\TenantBoundary;

/**
 * Returns one authorized authentication audit fact.
 */
final readonly class ShowAuthAuditAction
{
    /**
     * Create the audit detail use case.
     */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private TenantBoundary $boundary,
    ) {}

    /**
     * Authorize and return one route-resolved audit.
     */
    public function execute(Authenticatable $actor, AuthAudit $audit): AuthAudit
    {
        $this->features->assertAllowed(AuthFeature::Audit, FeatureOperation::Read);
        /** @var AuthAudit $record */
        $record = $this->boundary->query(AuthAudit::query(), 'auth.audits')
            ->whereKey($audit->getKey())->firstOrFail();
        $this->authorization->authorize($actor, 'nvl-auth.audits.view', $record);

        return $record;
    }
}
