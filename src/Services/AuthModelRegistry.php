<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;

/**
 * Resolves validated, host-extensible package model classes.
 */
final readonly class AuthModelRegistry
{
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
     * @template TModel of object
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

        return $configured;
    }
}
