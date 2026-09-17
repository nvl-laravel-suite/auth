<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\PermissionRegistrar;
use WeakReference;

/** Tracks retained RBAC principals so context changes cannot reuse loaded relations. */
final class RbacPrincipalTracker
{
    /** @var array<int, WeakReference<Model>> */
    private array $principals = [];

    public function __construct(private readonly PermissionRegistrar $registrar) {}

    public function track(Model $principal): void
    {
        $this->principals[spl_object_id($principal)] = WeakReference::create($principal);
    }

    public function clearRelations(): void
    {
        foreach ($this->principals as $identifier => $reference) {
            $principal = $reference->get();
            if (! $principal instanceof Model) {
                unset($this->principals[$identifier]);

                continue;
            }
            $principal->unsetRelation('roles')->unsetRelation('permissions');
            $this->registrar->forgetWildcardPermissionIndex($principal);
        }
    }
}
