<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Resolves membership principals through the independently configured RBAC model. */
final readonly class EloquentMembershipPrincipalResolver implements MembershipPrincipalResolver
{
    public function __construct(private AuthModelRegistry $models) {}

    public function resolve(SubjectReference $reference, bool $lock = false): Authenticatable
    {
        $class = $this->models->rbacPrincipalClass();
        $model = new $class;
        if ($reference->type !== $model->getMorphClass()) {
            throw new AuthException('membership_principal_unavailable', 'The membership principal is unavailable.', 404);
        }
        $query = $class::query()->where($model->getKeyName(), $reference->identifier);
        if ($lock) {
            $query->lockForUpdate();
        }
        $principal = $query->first();
        if (! $principal instanceof Authenticatable) {
            throw new AuthException('membership_principal_unavailable', 'The membership principal is unavailable.', 404);
        }
        $this->assertEligible($principal);

        return $principal;
    }

    public function assertEligible(Authenticatable $principal): void
    {
        if (! $principal instanceof Model
            || (method_exists($principal, 'isAuthenticationAllowed') && ! $principal->isAuthenticationAllowed())
            || ($principal->getAttribute('is_active') !== null && $principal->getAttribute('is_active') !== true)) {
            throw new AuthException('membership_principal_ineligible', 'The membership principal is ineligible.', 422);
        }
    }

    public function connectionName(): string
    {
        return (new ($this->models->rbacPrincipalClass()))->getConnection()->getName();
    }
}
