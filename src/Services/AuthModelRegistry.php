<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Support\Models\ConfiguredModelResolver;
use Nvl\Support\OwnerRegistry;

/**
 * Resolves validated, host-extensible package model classes.
 */
final readonly class AuthModelRegistry
{
    /** Retain the shared native identity registry rather than adding an Auth morph map. */
    public function __construct(private OwnerRegistry $identities) {}

    /** Resolve the exact native membership extension without changing its ownership strategy.
     * @return class-string<OwnerMembership>
     */
    public function ownerMembershipClass(): string
    {
        $base = OwnerMembership::class;
        $configured = config('nvl-auth.features.memberships.models.membership', $base);
        if (! is_string($configured)) {
            throw AuthException::invalidConfiguration('Owner memberships require a concrete configured model.');
        }
        $class = (new ConfiguredModelResolver)->resolve($configured, $base);
        $this->identities->registerReplacement('auth.memberships', $base, $class);

        return $class;
    }

    /**
     * Return the configured principal model.
     *
     * @return class-string<User>
     */
    public function userClass(): string
    {
        return $this->model('features.principal_management.models.user', User::class, User::class);
    }

    /**
     * Return the configured role model.
     *
     * @return class-string<Role>
     */
    public function roleClass(): string
    {
        return $this->model('features.rbac.models.role', Role::class, Role::class);
    }

    /**
     * Return the configured permission model.
     *
     * @return class-string<Permission>
     */
    public function permissionClass(): string
    {
        return $this->model('features.rbac.models.permission', Permission::class, Permission::class);
    }

    /**
     * Return the independently configured RBAC principal model.
     *
     * @return class-string<Model&Authenticatable>
     */
    public function rbacPrincipalClass(): string
    {
        $configured = config('nvl-auth.features.rbac.models.principal');
        $configured = is_string($configured) && trim($configured) !== ''
            ? $configured
            : $this->userClass();

        if (! is_a($configured, Model::class, true)
            || ! is_a($configured, Authenticatable::class, true)
            || ! method_exists($configured, 'roles')) {
            throw AuthException::invalidConfiguration(
                'The configured RBAC principal must be an Eloquent Authenticatable model using Spatie Permission HasRoles.',
            );
        }

        /** @var class-string<Model&Authenticatable> $configured */
        if (config('nvl-auth.ownership.scoped') === true) {
            $this->identities->register('auth.rbac-principal', $configured);
        }

        return $configured;
    }

    /**
     * Return the configured Sanctum token model.
     *
     * @return class-string<PersonalAccessToken>
     */
    public function personalAccessTokenClass(): string
    {
        return $this->model(
            'features.api_tokens.models.personal_access_token',
            PersonalAccessToken::class,
            PersonalAccessToken::class,
        );
    }

    /**
     * Validate one configured model subclass.
     *
     * @template TModel of Model
     *
     * @param  class-string<TModel>  $default
     * @param  class-string<TModel>  $base
     * @return class-string<TModel>
     */
    private function model(string $path, string $default, string $base): string
    {
        $configured = config("nvl-auth.{$path}", $default);

        if (! is_string($configured) || ! is_a($configured, $base, true)) {
            throw AuthException::invalidConfiguration(
                "Auth model [{$path}] must extend [{$base}].",
            );
        }

        if (config('nvl-auth.ownership.scoped') === true) {
            $configured = (new ConfiguredModelResolver)->resolve($configured, $base);
            $this->identities->registerReplacement('auth.models.'.strtolower((new \ReflectionClass($base))->getShortName()), $base, $configured);
        }

        return $configured;
    }
}
