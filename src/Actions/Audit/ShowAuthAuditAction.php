<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Audit;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

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
    ) {}

    /**
     * Authorize and return one route-resolved audit.
     */
    public function execute(Authenticatable $actor, AuthAudit $audit): AuthAudit
    {
        $this->features->assertAllowed(AuthFeature::Audit, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.audits.view', $audit);

        return $audit;
    }
}
