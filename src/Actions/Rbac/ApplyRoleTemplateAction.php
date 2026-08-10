<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Data\Mutations\ApplyRoleTemplateData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;
use Nvl\Auth\Services\RoleHierarchy;
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
        private RbacEntityLocator $entities,
        private RoleHierarchy $hierarchy,
        private AuthAuditRecorder $audits,
    ) {}

    /** Apply one named template. */
    public function execute(Authenticatable $actor, ApplyRoleTemplateData $data): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.manageRoles');
        $templates = $this->templates->roles();
        $templateKey = trim($data->template);

        if (! array_key_exists($templateKey, $templates)) {
            throw new AuthException('role_template_not_found', 'The requested role template does not exist.', 404);
        }

        $template = $templates[$templateKey];
        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $connection = (new $roleClass)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $data, $guard, $permissionClass, $roleClass, $template, $templateKey): Role {
            $parent = $template->parentRole !== null
                ? $this->entities->roleByName($template->parentRole, $guard)
                : null;
            $mutation = $template->toMutation($data->roleName, $parent?->id);
            $role = $roleClass::findOrCreate($mutation->name, $guard);

            if (! $role instanceof Role) {
                throw AuthException::invalidConfiguration('The configured role model must extend the package Role model.');
            }

            $this->hierarchy->assertParentAllowed($role, $parent);
            $permissions = [];

            foreach ($mutation->permissions as $name) {
                $permissions[] = $permissionClass::findOrCreate($name, $guard);
            }

            $attributes = $mutation->except('permissions')->toModelPatch();
            $attributes['is_system'] = $attributes['system'];
            unset($attributes['system']);
            $role->fill($attributes)->save();
            $role->syncPermissions($permissions);
            $this->audits->record('role.template_applied', actor: $actor, metadata: [
                'role_id' => $role->id,
                'template' => $templateKey,
                'target_role' => $mutation->name,
            ]);
            RbacChanged::dispatch('role', $role->id, 'template_applied', [
                'template' => $templateKey,
                'target_role' => $mutation->name,
            ]);

            return $role->refresh()->load(['parent', 'permissions']);
        }, 3);
    }
}
