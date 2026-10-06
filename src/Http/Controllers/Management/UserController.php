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
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\BulkUserData;
use Nvl\Auth\Data\Mutations\StoreUserData;
use Nvl\Auth\Data\Mutations\SyncUserPermissionsData;
use Nvl\Auth\Data\Mutations\SyncUserRolesData;
use Nvl\Auth\Data\Mutations\UpdateUserData;
use Nvl\Auth\Data\Mutations\UpdateUserStatusData;
use Nvl\Auth\Data\Queries\UserIndexQueryData;
use Nvl\Auth\Data\Queries\UserSuggestionQueryData;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Http\AuthRequestInput;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;

/** Handles package-owned principal management API transport. */
final class UserController extends AuthenticatedController
{
    /** List principals. */
    public function index(Request $request, ListUsersAction $action): JsonResponse
    {
        $query = UserIndexQueryData::validateAndCreate($request->all());
        $page = $action->execute(
            $this->subject($request),
            $query->search,
            $query->active,
            $query->trashed ?? 'without',
            $query->role,
            $query->perPage ?? 25,
        );

        return response()->json(['data' => $page, 'code' => 'users_listed', 'message' => trans('nvl-auth::responsecode.users_listed')]);
    }

    /** Return minimal principal suggestions. */
    public function suggestions(Request $request, SuggestUsersAction $action): JsonResponse
    {
        $query = UserSuggestionQueryData::validateAndCreate($request->all());

        return response()->json([
            'data' => $action->execute(
                $this->subject($request),
                $query->search,
                $query->limit,
            ),
            'code' => 'user_suggestions_listed', 'message' => trans('nvl-auth::responsecode.user_suggestions_listed'),
        ]);
    }

    /** Create a principal. */
    public function store(StoreUserData $data, Request $request, CreateUserAction $action): JsonResponse
    {
        if (! $request->has('locale')) {
            $data->locale = Config::string('nvl-auth.features.principal_management.settings.default_locale', 'en');
        }
        if (! $request->has('timezone')) {
            $data->timezone = Config::string('nvl-auth.features.principal_management.settings.default_timezone', 'UTC');
        }

        $user = $action->execute($this->subject($request), $data);

        return response()->json(['data' => $user, 'code' => 'user_created', 'message' => trans('nvl-auth::responsecode.user_created')], 201);
    }

    /** Show one principal, including soft-deleted principals. */
    public function show(Request $request, string $user, ShowUserAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $user),
            'code' => 'user_shown', 'message' => trans('nvl-auth::responsecode.user_shown'),
        ]);
    }

    /** Update one principal. */
    public function update(Request $request, string $user, UpdateUserAction $action): JsonResponse
    {
        $data = UpdateUserData::validateForUpdate($this->requestPayload($request), $user);
        $updated = $action->execute($this->subject($request), $user, $data);

        return response()->json(['data' => $updated, 'code' => 'user_updated', 'message' => trans('nvl-auth::responsecode.user_updated')]);
    }

    /** Enable or disable one principal. */
    public function status(
        UpdateUserStatusData $data,
        Request $request,
        string $user,
        SetUserActiveAction $action,
        PrincipalAttributeMapper $attributes,
    ): JsonResponse {
        $updated = $action->execute($this->subject($request), $user, $data);
        $active = (bool) $attributes->value($updated, PrincipalAttribute::Active);

        return response()->json([
            'data' => $updated,
            'code' => $active ? 'user_enabled' : 'user_disabled',
            'message' => $active ? trans('nvl-auth::responsecode.user_enabled') : trans('nvl-auth::responsecode.user_disabled'),
        ]);
    }

    /** Soft delete one principal. */
    public function destroy(Request $request, string $user, DeleteUserAction $action): JsonResponse
    {
        $action->execute($this->subject($request), $user);

        return response()->json(['data' => null, 'code' => 'user_deleted', 'message' => trans('nvl-auth::responsecode.user_deleted')]);
    }

    /** Restore one principal. */
    public function restore(Request $request, string $user, RestoreUserAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $user),
            'code' => 'user_restored', 'message' => trans('nvl-auth::responsecode.user_restored'),
        ]);
    }

    /** Apply one bounded bulk lifecycle operation. */
    public function bulk(Request $request, BulkUpdateUsersAction $action): JsonResponse
    {
        $data = BulkUserData::validateAndCreate(AuthRequestInput::aliased($request->all(), ['user_ids' => ['userIds']]));
        $result = $action->execute($this->subject($request), $data->operation, $data->userIds);

        return response()->json(['data' => $result, 'code' => 'users_bulk_updated', 'message' => trans('nvl-auth::responsecode.users_bulk_updated')]);
    }

    /** Replace one principal's roles. */
    public function roles(SyncUserRolesData $data, Request $request, string $user, SyncUserRolesAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $user, $data),
            'code' => 'user_roles_synchronized', 'message' => trans('nvl-auth::responsecode.user_roles_synchronized'),
        ]);
    }

    /** Replace one principal's direct permissions. */
    public function permissions(SyncUserPermissionsData $data, Request $request, string $user, SyncUserPermissionsAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request), $user, $data),
            'code' => 'user_permissions_synchronized', 'message' => trans('nvl-auth::responsecode.user_permissions_synchronized'),
        ]);
    }
}
