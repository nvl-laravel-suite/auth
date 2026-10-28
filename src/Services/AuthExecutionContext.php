<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Ownership\Contracts\OwnershipRunner;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;
use Spatie\Permission\PermissionRegistrar;

/** Request-scoped verified identity overlay facts; never queue execution authority. @api */
final class AuthExecutionContext
{
    /** @var array{actor_type: string, actor_id: string, effective_subject_type: string, effective_subject_id: string, impersonation_id: string}|null */
    private ?array $active = null;

    public function __construct(private readonly Container $container) {}

    /** @return array{actor_type: string, actor_id: string, effective_subject_type: string, effective_subject_id: string, impersonation_id: string}|null */
    public function facts(): ?array
    {
        return $this->active;
    }

    public function assertNativeMutationAllowed(): void
    {
        if ($this->active !== null) {
            throw new AuthException('impersonation_operation_forbidden', 'This security operation is unavailable while impersonating.', 403);
        }
    }

    /** Re-admit the durable grant before exposing a target; caller fields never establish an overlay.
     * @template TResult
     *
     * @param  Closure(Authenticatable, Authenticatable): TResult  $callback
     * @return TResult
     */
    public function run(Authenticatable $actor, string $impersonationId, AuthenticationRequestContext $context, Closure $callback): mixed
    {
        $this->assertNativeMutationAllowed();
        $admitted = $this->container->make(AuthImpersonation::class)->admit($actor, $impersonationId, $context);
        $a = SubjectReference::fromAuthenticatable($admitted['actor']);
        $t = SubjectReference::fromAuthenticatable($admitted['target']);

        $rbac = config('nvl-auth.features.rbac.enabled') === true && class_exists(PermissionRegistrar::class);
        try {
            if ($rbac) {
                $tracker = $this->container->make(RbacPrincipalTracker::class);
                $tracker->track($admitted['actor']);
                $tracker->track($admitted['target']);
                $tracker->clearRelations();
            }
            $execute = function () use ($admitted, $a, $t, $callback): mixed {
                $this->active = ['actor_type' => $a->type, 'actor_id' => $a->identifier, 'effective_subject_type' => $t->type, 'effective_subject_id' => $t->identifier, 'impersonation_id' => $admitted['grant']->identifier()];

                return $callback($admitted['target'], $admitted['actor']);
            };
            $owner = $admitted['grant']->owner_reference;
            if ($owner !== null) {
                $reference = OwnerReference::fromArray($owner);
                $model = $this->container->make(OwnerIdentityResolver::class)->resolve($reference);

                return $this->container->make(OwnershipRunner::class)->run($model, $admitted['target'], $execute);
            }

            return $execute();
        } finally {
            $this->active = null;
            if ($rbac) {
                $this->container->make(RbacPrincipalTracker::class)->clearRelations();
            }
        }
    }

    public function __serialize(): never
    {
        throw new \LogicException('Execution authority cannot be serialized into a job.');
    }
}
