<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\AuthUserReader;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\BulkUserData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StoreUserData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\SyncUserPermissionsData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\SyncUserRolesData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdateUserData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdateUserStatusData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\UserIndexQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\UserSuggestionQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;
use Spatie\LaravelData\Optional;

/** Handles package-owned principal management API transport. */
final class UserController extends AuthenticatedController
{
    /** List principals. */
    public function index(Request $request, AuthUserReader $action): JsonResponse
    {
        $query = UserIndexQueryData::validateAndCreate($request->all());
        $page = $action->paginate(
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
    public function suggestions(Request $request, AuthUserReader $action): JsonResponse
    {
        $query = UserSuggestionQueryData::validateAndCreate($request->all());

        return response()->json([
            'data' => $action->suggest(
                $this->subject($request),
                $query->search,
                $query->limit,
            ),
            'code' => 'user_suggestions_listed', 'message' => trans('nvl-auth::responsecode.user_suggestions_listed'),
        ]);
    }

    /** Create a principal. */
    public function store(StoreUserData $data, Request $request, AuthUsers $action): JsonResponse
    {
        if (! $request->has('locale')) {
            $data->locale = Config::string('nvl-auth.features.principal_management.settings.default_locale', 'en');
        }
        if (! $request->has('timezone')) {
            $data->timezone = Config::string('nvl-auth.features.principal_management.settings.default_timezone', 'UTC');
        }

        $user = $action->create($this->subject($request), array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional));

        return response()->json(['data' => $user, 'code' => 'user_created', 'message' => trans('nvl-auth::responsecode.user_created')], 201);
    }

    /** Show one principal, including soft-deleted principals. */
    public function show(Request $request, string $user, AuthUserReader $action): JsonResponse
    {
        return response()->json([
            'data' => $action->find($this->subject($request), $user),
            'code' => 'user_shown', 'message' => trans('nvl-auth::responsecode.user_shown'),
        ]);
    }

    /** Update one principal. */
    public function update(Request $request, string $user, AuthUsers $action): JsonResponse
    {
        $data = UpdateUserData::validateForUpdate($this->requestPayload($request), $user);
        $updated = $action->update($this->subject($request), $user, array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional));

        return response()->json(['data' => $updated, 'code' => 'user_updated', 'message' => trans('nvl-auth::responsecode.user_updated')]);
    }

    /** Enable or disable one principal. */
    public function status(
        UpdateUserStatusData $data,
        Request $request,
        string $user,
        AuthUsers $action,
        PrincipalAttributeMapper $attributes,
    ): JsonResponse {
        $updated = $action->setActive($this->subject($request), $user, array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional));
        $active = (bool) $attributes->value($updated, PrincipalAttribute::Active);

        return response()->json([
            'data' => $updated,
            'code' => $active ? 'user_enabled' : 'user_disabled',
            'message' => $active ? trans('nvl-auth::responsecode.user_enabled') : trans('nvl-auth::responsecode.user_disabled'),
        ]);
    }

    /** Soft delete one principal. */
    public function destroy(Request $request, string $user, AuthUsers $action): JsonResponse
    {
        $action->delete($this->subject($request), $user);

        return response()->json(['data' => null, 'code' => 'user_deleted', 'message' => trans('nvl-auth::responsecode.user_deleted')]);
    }

    /** Restore one principal. */
    public function restore(Request $request, string $user, AuthUsers $action): JsonResponse
    {
        return response()->json([
            'data' => $action->restore($this->subject($request), $user),
            'code' => 'user_restored', 'message' => trans('nvl-auth::responsecode.user_restored'),
        ]);
    }

    /** Apply one bounded bulk lifecycle operation. */
    public function bulk(Request $request, AuthUsers $action): JsonResponse
    {
        $data = BulkUserData::validateAndCreate(AuthRequestInput::aliased($request->all(), ['user_ids' => ['userIds']]));
        $result = $action->bulkUpdate($this->subject($request), $data->operation, $data->userIds);

        return response()->json(['data' => $result, 'code' => 'users_bulk_updated', 'message' => trans('nvl-auth::responsecode.users_bulk_updated')]);
    }

    /** Replace one principal's roles. */
    public function roles(SyncUserRolesData $data, Request $request, string $user, AuthRoles $action): JsonResponse
    {
        return response()->json([
            'data' => $action->syncUserRoles($this->subject($request), $user, array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional)),
            'code' => 'user_roles_synchronized', 'message' => trans('nvl-auth::responsecode.user_roles_synchronized'),
        ]);
    }

    /** Replace one principal's direct permissions. */
    public function permissions(SyncUserPermissionsData $data, Request $request, string $user, AuthPermissions $action): JsonResponse
    {
        return response()->json([
            'data' => $action->syncUserPermissions($this->subject($request), $user, array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional)),
            'code' => 'user_permissions_synchronized', 'message' => trans('nvl-auth::responsecode.user_permissions_synchronized'),
        ]);
    }
}
