<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Data\Mutations\UpdateProfileData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Updates the authenticated principal's self-service profile fields.
 */
final readonly class UpdateProfileAction
{
    /** Create the profile mutation use case. */
    public function __construct(
        private FeatureGate $features,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
    ) {}

    /** Persist self-service profile changes. */
    public function execute(Authenticatable $subject, UpdateProfileData $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $user = $this->users->authenticated($subject);

        return DB::connection($user->getConnectionName())->transaction(function () use ($data, $user): User {
            $user->fill([
                'name' => trim($data->name),
                'locale' => trim($data->locale),
                'timezone' => trim($data->timezone),
                'profile' => $data->profile,
                'preferences' => $data->preferences,
            ])->save();
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->audits->record('profile.updated', subject: $reference, actor: $user);
            PrincipalChanged::dispatch($user->id, 'profile_updated');

            return $user->refresh();
        }, 3);
    }
}
