<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Enums\UserBulkOperation;
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

/** Handles package-owned principal management API transport. */
final class UserController extends AuthenticatedController
{
    /** List principals. */
    public function index(Request $request, AuthUserReader $action): JsonResponse
    {
        $query = array_replace(['search' => null, 'active' => null, 'trashed' => null, 'role' => null, 'per_page' => null], Validator::make(AuthRequestInput::aliased($request->all(), ['per_page' => ['perPage']]), UserIndexQueryData::rules())->validate());
        if (isset($query['active'])) {
            $query['active'] = (bool) $query['active'];
        }
        if (isset($query['per_page'])) {
            $query['per_page'] = (int) $query['per_page'];
        }

        $page = $action->paginate(
            $this->subject($request),
            $query['search'],
            $query['active'],
            $query['trashed'] ?? 'without',
            $query['role'],
            $query['per_page'] ?? 25,
        );

        return response()->json(['data' => $page, 'code' => 'users_listed', 'message' => trans('nvl-auth::responsecode.users_listed')]);
    }

    /** Return minimal principal suggestions. */
    public function suggestions(Request $request, AuthUserReader $action): JsonResponse
    {
        $query = array_replace(['limit' => null], Validator::make($request->all(), UserSuggestionQueryData::rules())->validate());
        if (isset($query['limit'])) {
            $query['limit'] = (int) $query['limit'];
        }

        return response()->json([
            'data' => $action->suggest(
                $this->subject($request),
                $query['search'],
                $query['limit'],
            ),
            'code' => 'user_suggestions_listed', 'message' => trans('nvl-auth::responsecode.user_suggestions_listed'),
        ]);
    }

    /** Create a principal. */
    public function store(Request $request, AuthUsers $action): JsonResponse
    {
        $data = array_replace(['password' => null, 'active' => true, 'locale' => 'en', 'timezone' => 'UTC', 'profile' => [], 'preferences' => [], 'roles' => [], 'permissions' => [], 'emailVerified' => false], Validator::make(AuthRequestInput::aliased($request->all(), ['emailVerified' => ['email_verified']]), StoreUserData::rules())->validate());
        if (isset($data['active'])) {
            $data['active'] = (bool) $data['active'];
        }
        if (isset($data['emailVerified'])) {
            $data['emailVerified'] = (bool) $data['emailVerified'];
        }

        if (! $request->has('locale')) {
            $data['locale'] = Config::string('nvl-auth.features.principal_management.settings.default_locale', 'en');
        }
        if (! $request->has('timezone')) {
            $data['timezone'] = Config::string('nvl-auth.features.principal_management.settings.default_timezone', 'UTC');
        }

        $user = $action->create($this->subject($request), $data);

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
        $updated = $action->update($this->subject($request), $user, $data);

        return response()->json(['data' => $updated, 'code' => 'user_updated', 'message' => trans('nvl-auth::responsecode.user_updated')]);
    }

    /** Enable or disable one principal. */
    public function status(
        Request $request,
        string $user,
        AuthUsers $action,
        PrincipalAttributeMapper $attributes,
    ): JsonResponse {
        $data = Validator::make($request->all(), UpdateUserStatusData::rules())->validate();
        if (isset($data['active'])) {
            $data['active'] = (bool) $data['active'];
        }

        $updated = $action->setActive($this->subject($request), $user, $data);
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
        $data = Validator::make(AuthRequestInput::aliased($request->all(), ['user_ids' => ['userIds']]), BulkUserData::rules())->validate();
        $result = $action->bulkUpdate($this->subject($request), UserBulkOperation::from($data['operation']), $data['user_ids']);

        return response()->json(['data' => $result, 'code' => 'users_bulk_updated', 'message' => trans('nvl-auth::responsecode.users_bulk_updated')]);
    }

    /** Replace one principal's roles. */
    public function roles(Request $request, string $user, AuthRoles $action): JsonResponse
    {
        $data = Validator::make($request->all(), SyncUserRolesData::rules())->validate();

        return response()->json([
            'data' => $action->syncUserRoles($this->subject($request), $user, $data),
            'code' => 'user_roles_synchronized', 'message' => trans('nvl-auth::responsecode.user_roles_synchronized'),
        ]);
    }

    /** Replace one principal's direct permissions. */
    public function permissions(Request $request, string $user, AuthPermissions $action): JsonResponse
    {
        $data = Validator::make($request->all(), SyncUserPermissionsData::rules())->validate();

        return response()->json([
            'data' => $action->syncUserPermissions($this->subject($request), $user, $data),
            'code' => 'user_permissions_synchronized', 'message' => trans('nvl-auth::responsecode.user_permissions_synchronized'),
        ]);
    }
}
