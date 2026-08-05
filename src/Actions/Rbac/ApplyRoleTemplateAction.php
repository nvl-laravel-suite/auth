<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RoleTemplateRegistry;

/** Creates or updates one role from the canonical template registry. */
final readonly class ApplyRoleTemplateAction
{
    /** Create the template application use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
        private RoleTemplateRegistry $templates,
        private AuthAuditRecorder $audits,
    ) {}

    /** Apply one named template. */
    public function execute(Authenticatable $actor, string $template): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.manageRoles');
        $templates = $this->templates->roles();

        if (! array_key_exists($template, $templates)) {
            throw new AuthException('role_template_not_found', 'The requested role template does not exist.', 404);
        }

        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = (new $roleClass)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $guard, $permissionClass, $roleClass, $template, $templates): Role {
            $role = $roleClass::findOrCreate($template, $guard);

            if (! $role instanceof Role) {
                throw AuthException::invalidConfiguration('The configured role model must extend the package Role model.');
            }

            $permissions = [];

            foreach ($templates[$template] as $name) {
                $permissions[] = $permissionClass::findOrCreate($name, $guard);
            }

            $role->forceFill(['is_system' => true])->save();
            $role->syncPermissions($permissions);
            $this->audits->record('role.template_applied', actor: $actor, metadata: ['role_id' => $role->id, 'template' => $template]);
            RbacChanged::dispatch('role', $role->id, 'template_applied', ['template' => $template]);

            return $role->refresh()->load('permissions');
        }, 3);
    }
}
