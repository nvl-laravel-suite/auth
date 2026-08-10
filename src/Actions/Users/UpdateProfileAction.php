<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\UpdateProfileData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Models\User;
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
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** Persist self-service profile changes. */
    public function execute(Authenticatable $subject, UpdateProfileData $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $user = $this->users->authenticated($subject);

        return DB::connection($user->getConnectionName())->transaction(function () use ($data, $user): User {
            $user->forceFill($this->attributes->map([
                PrincipalAttribute::Name->value => trim($data->name),
                PrincipalAttribute::Locale->value => trim($data->locale),
                PrincipalAttribute::Timezone->value => trim($data->timezone),
                PrincipalAttribute::Profile->value => $data->profile,
                PrincipalAttribute::Preferences->value => $data->preferences,
            ]))->save();
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->audits->record('profile.updated', subject: $reference, actor: $user);
            PrincipalChanged::dispatch($this->attributes->identifier($user), 'profile_updated');

            return $user->refresh();
        }, 3);
    }
}
