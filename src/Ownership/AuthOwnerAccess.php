<?php

declare(strict_types=1);

namespace Nvl\Auth\Ownership;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Support\Ownership\Contracts\OwnershipReadiness;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Optional NVL membership adapter; hosts may use their own OwnerAccess with no membership tables. @api */
final readonly class AuthOwnerAccess implements OwnerAccess
{
    public function __construct(private OwnerIdentityResolver $owners, private AuthModelRegistry $models, private MembershipPrincipalResolver $principals, private OwnershipReadiness $readiness) {}

    /** Revalidate persisted membership before the runner installs any owner context. */
    public function assertCanEnter(Authenticatable $actor, Model $owner): void
    {
        $this->readiness->assertActive('auth.memberships');
        $reference = $this->owners->reference($owner);
        $subject = SubjectReference::fromAuthenticatable($actor);
        $this->principals->resolve($subject);
        $class = $this->models->ownerMembershipClass();
        $model = new $class;
        $row = $model->getConnection()->table($model->getTable())->useWritePdo()
            ->where('owner_scope_key', $reference->scopeKey())->where('subject_type', $subject->type)->where('subject_id', $subject->identifier)
            ->where('status', 'active')->first();
        $stored = $row?->owner_reference;
        if (! is_string($stored) || OwnerReference::fromJson($stored) != $reference) {
            throw new AuthException('owner_membership_required', 'An active owner membership is required.', 403);
        }
    }
}
