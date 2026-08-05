<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Nvl\Auth\Actions\Users\BulkUpdateUsersAction;
use Nvl\Auth\Actions\Users\CreateUserAction;
use Nvl\Auth\Actions\Users\DeleteUserAction;
use Nvl\Auth\Actions\Users\ListUsersAction;
use Nvl\Auth\Actions\Users\RestoreUserAction;
use Nvl\Auth\Actions\Users\SetUserActiveAction;
use Nvl\Auth\Actions\Users\ShowUserAction;
use Nvl\Auth\Actions\Users\SuggestUsersAction;
use Nvl\Auth\Actions\Users\SyncUserPermissionsAction;
use Nvl\Auth\Actions\Users\SyncUserRolesAction;
use Nvl\Auth\Actions\Users\UpdateUserAction;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\Http\Requests\BulkUserRequest;
use Nvl\Auth\Http\Requests\StoreUserRequest;
use Nvl\Auth\Http\Requests\SyncUserPermissionsRequest;
use Nvl\Auth\Http\Requests\SyncUserRolesRequest;
use Nvl\Auth\Http\Requests\UpdateUserRequest;
use Nvl\Auth\ValueObjects\CreateUserData;
use Nvl\Auth\ValueObjects\UpdateUserData;

/** Handles package-owned principal management API transport. */
final class UserController extends AuthenticatedController
{
    /** List principals. */
    public function index(Request $request, ListUsersAction $action): JsonResponse
    {
        $request->validate([
            'search' => ['sometimes', 'string', 'max:160'],
            'active' => ['sometimes', 'boolean'],
            'trashed' => ['sometimes', 'in:without,with,only'],
            'role' => ['sometimes', 'string', 'max:160'],
            'per_page' => ['sometimes', 'integer', 'between:1,100'],
        ]);
        $page = $action->execute(
            $this->subject($request),
            $this->optionalStringInput($request, 'search'),
            $request->has('active') ? $request->boolean('active') : null,
            $this->optionalStringInput($request, 'trashed') ?? 'without',
            $this->optionalStringInput($request, 'role'),
            (int) $request->integer('per_page', 25),
        );

        return response()->json(['data' => $page, 'code' => 'users_listed', 'message' => 'Users were listed.']);
    }

    /** Return minimal principal suggestions. */
    public function suggestions(Request $request, SuggestUsersAction $action): JsonResponse
    {
        $request->validate(['search' => ['required', 'string', 'min:1', 'max:160'], 'limit' => ['sometimes', 'integer', 'between:1,100']]);

        return response()->json([
            'data' => $action->execute(
                $this->subject($request),
                $this->stringInput($request, 'search'),
                $request->has('limit') ? (int) $request->integer('limit') : null,
            ),
            'code' => 'user_suggestions_listed',
            'message' => 'User suggestions were listed.',
        ]);
    }

    /** Create a principal. */
    public function store(StoreUserRequest $request, CreateUserAction $action): JsonResponse
    {
        $user = $action->execute($this->subject($request), new CreateUserData(
            name: $this->stringInput($request, 'name'),
            email: $this->stringInput($request, 'email'),
            password: $this->optionalStringInput($request, 'password'),
            active: $request->missing('active') || $request->boolean('active'),
            locale: $this->optionalStringInput($request, 'locale') ?? Config::string('nvl-auth.features.principal_management.settings.default_locale', 'en'),
            timezone: $this->optionalStringInput($request, 'timezone') ?? Config::string('nvl-auth.features.principal_management.settings.default_timezone', 'UTC'),
            profile: $this->associativeInput($request, 'profile'),
            preferences: $this->associativeInput($request, 'preferences'),
            roles: $this->stringListInput($request, 'roles'),
            permissions: $this->stringListInput($request, 'permissions'),
            emailVerified: $request->boolean('email_verified'),
        ));

        return response()->json(['data' => $user, 'code' => 'user_created', 'message' => 'The user was created.'], 201);
    }

    /** Show one principal, including soft-deleted principals. */
    public function show(Request $request, string $user, ShowUserAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $user),
            'code' => 'user_shown',
            'message' => 'The user was shown.',
        ]);
    }

    /** Update one principal. */
    public function update(UpdateUserRequest $request, string $user, UpdateUserAction $action): JsonResponse
    {
        $updated = $action->execute($this->subject($request), $user, new UpdateUserData(
            name: $this->optionalStringInput($request, 'name'),
            email: $this->optionalStringInput($request, 'email'),
            password: $this->optionalStringInput($request, 'password'),
            locale: $this->optionalStringInput($request, 'locale'),
            timezone: $this->optionalStringInput($request, 'timezone'),
            profile: $request->has('profile') ? $this->associativeInput($request, 'profile') : null,
            preferences: $request->has('preferences') ? $this->associativeInput($request, 'preferences') : null,
            emailVerified: $request->has('email_verified') ? $request->boolean('email_verified') : null,
        ));

        return response()->json(['data' => $updated, 'code' => 'user_updated', 'message' => 'The user was updated.']);
    }

    /** Enable or disable one principal. */
    public function status(Request $request, string $user, SetUserActiveAction $action): JsonResponse
    {
        $request->validate(['active' => ['required', 'boolean']]);
        $updated = $action->execute($this->subject($request), $user, $request->boolean('active'));

        return response()->json([
            'data' => $updated,
            'code' => $updated->is_active ? 'user_enabled' : 'user_disabled',
            'message' => $updated->is_active ? 'The user was enabled.' : 'The user was disabled.',
        ]);
    }

    /** Soft delete one principal. */
    public function destroy(Request $request, string $user, DeleteUserAction $action): JsonResponse
    {
        $action->execute($this->subject($request), $user);

        return response()->json(['data' => null, 'code' => 'user_deleted', 'message' => 'The user was deleted.']);
    }

    /** Restore one principal. */
    public function restore(Request $request, string $user, RestoreUserAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $user),
            'code' => 'user_restored',
            'message' => 'The user was restored.',
        ]);
    }

    /** Apply one bounded bulk lifecycle operation. */
    public function bulk(BulkUserRequest $request, BulkUpdateUsersAction $action): JsonResponse
    {
        $operation = UserBulkOperation::from($this->stringInput($request, 'operation'));
        $result = $action->execute($this->subject($request), $operation, $this->stringListInput($request, 'user_ids'));

        return response()->json(['data' => $result, 'code' => 'users_bulk_updated', 'message' => 'The bulk user operation completed.']);
    }

    /** Replace one principal's roles. */
    public function roles(SyncUserRolesRequest $request, string $user, SyncUserRolesAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $user, $this->stringListInput($request, 'roles')),
            'code' => 'user_roles_synchronized',
            'message' => 'The user roles were synchronized.',
        ]);
    }

    /** Replace one principal's direct permissions. */
    public function permissions(SyncUserPermissionsRequest $request, string $user, SyncUserPermissionsAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $user, $this->stringListInput($request, 'permissions')),
            'code' => 'user_permissions_synchronized',
            'message' => 'The user permissions were synchronized.',
        ]);
    }
}
