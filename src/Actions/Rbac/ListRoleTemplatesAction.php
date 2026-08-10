<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RoleTemplateRegistry;

/** Lists the merged package and consumer-contributed role templates. */
final readonly class ListRoleTemplatesAction
{
    /** Create the template listing use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RoleTemplateRegistry $templates,
    ) {}

    /**
     * Return every validated template with presentation and hierarchy metadata.
     *
     * @return list<array<string, mixed>>
     */
    public function execute(Authenticatable $actor): array
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');

        return array_values(array_map(
            static fn ($template): array => $template->toArray(),
            $this->templates->roles(),
        ));
    }
}
