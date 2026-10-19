<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Nvl\Auth\Enums\MembershipStatus;

/**
 * Supplies neutral membership identity and lifecycle to native ownership and the legacy adapter.
 *
 * @property string $subject_type
 * @property string $subject_id
 * @property MembershipStatus $status
 * @property bool $is_owner
 * @property int $revision
 * @property string|null $tenant_id
 *
 * @api
 */
abstract class Membership extends AuthModel
{
    /** @return array<string,string> */
    protected function casts(): array
    {
        return ['status' => MembershipStatus::class, 'is_owner' => 'boolean', 'revision' => 'integer'];
    }
}
