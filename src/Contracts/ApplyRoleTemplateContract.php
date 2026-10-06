<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\ApplyRoleTemplateData;
use Nvl\Auth\Models\Role;

/**
 * Defines the apply role template use-case boundary.
 *
 * @api
 */
interface ApplyRoleTemplateContract
{
    /** Apply one named template. */
    public function execute(Authenticatable $actor, ApplyRoleTemplateData $data): Role;
}
