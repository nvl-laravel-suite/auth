<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\RegistrationAdmission;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalMutation;
use Nvl\Auth\Enums\RegistrationMethod;
use Nvl\Auth\Events\PrincipalRegistered;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\User;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\DomainEventDispatcher;

/**
 * Completes native password signup; the consumer commits before authenticating.
 *
 * @api
 */
final readonly class AuthRegistration
{
    public function __construct(private AuthModelRegistry $models, private ConfiguredRegistrationAdmission $nativeAdmission, private RegistrationAdmission $admission, private PrincipalExtensions $extensions, private PrincipalAttributeMapper $attributes, private PasswordValidationRules $passwordPolicy, private PasswordUpdater $passwords, private FeatureGate $features, private AuthConfiguration $configuration, private AuthOperationBoundary $operations, private PrincipalSecurity $security, private AuthCommittedAudit $audits, private DomainEventDispatcher $events, private AuthEmailVerification $verification, private AuthPipeline $pipeline) {}

    /**
     * Create one active unverified principal without session, membership or RBAC effects.
     *
     * @param  array<string, mixed>  $data
     */
    public function register(#[\SensitiveParameter] array $data): User
    {
        $this->nativeAdmission->assertProvisioningAllowed();
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Issue);
        $this->operations->central(AuthIdentityOperation::Registration);
        $data = $this->validate($data);
        $class = $this->models->userClass();
        $prototype = new $class;
        PrincipalEmailIdentity::assertReady($prototype);
        $connection = $prototype->getConnection();
        if ($connection !== (new AuthAudit)->getConnection() || $connection !== (new Challenge)->getConnection()) {
            throw AuthException::invalidConfiguration('Registration requires principal, proof and audit storage on one source.');
        }

        return $connection->transaction(function () use ($data, $class, $connection): User {
            return $this->pipeline->run('registration', new AuthPipelineContext('registration', ['method' => 'password', 'attributes' => array_keys($data)]), function () use ($data, $class, $connection): User {
                $this->nativeAdmission->assertProvisioningAllowed();
                $mapped = $this->attributes->map(['name' => trim($data['name']), 'email' => $data['email'], 'active' => true, 'emailVerified' => false, 'locale' => $data['locale'], 'timezone' => $data['timezone'], 'profile' => [], 'preferences' => []]);
                $extensions = $this->extensions->map(PrincipalMutation::Registration, $data['extensions'], occupiedColumns: array_keys($mapped));
                $this->admission->assertAllowed(RegistrationMethod::Password, $data['email'], $extensions);
                $this->nativeAdmission->assertProvisioningAllowed();
                $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Issue);
                try {
                    $user = $class::query()->create($mapped + $extensions);
                } catch (UniqueConstraintViolationException $exception) {
                    throw new AuthException('registration_unavailable', 'Registration is unavailable.', 409, previous: $exception);
                }
                $this->passwords->update($user, $data['password']);
                $user->setRememberToken(Str::random(60));
                $user->save();
                $this->security->lock($user);
                $reference = SubjectReference::fromAuthenticatable($user);
                $this->audits->record($connection, 'registration.completed', subject: $reference, metadata: ['method' => RegistrationMethod::Password->value]);
                $this->events->dispatch(new PrincipalRegistered($reference, RegistrationMethod::Password), $connection);
                if ($this->configuration->featureEnabled(AuthFeature::EmailVerification)) {
                    $this->verification->request($user, $data['locale']);
                }

                return $user->refresh();
            });
        }, 3);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, email: string, password: string, locale: string, timezone: string, extensions: array<array-key, mixed>}
     */
    private function validate(#[\SensitiveParameter] array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'email', 'password', 'passwordConfirmation', 'locale', 'timezone', 'extensions']) !== []) {
            throw new InvalidArgumentException('Unknown or protected registration input fields.');
        }
        $data += ['locale' => $this->configuration->string('features.principal_management.settings.default_locale', 'en'), 'timezone' => $this->configuration->string('features.principal_management.settings.default_timezone', 'UTC'), 'extensions' => []];
        if (! is_string($data['name'] ?? null) || ! is_string($data['email'] ?? null) || ! is_string($data['password'] ?? null)
            || ! is_string($data['passwordConfirmation'] ?? null) || ! is_string($data['locale']) || ! is_string($data['timezone']) || ! is_array($data['extensions'])) {
            throw new InvalidArgumentException('Invalid registration input.');
        }
        $email = PrincipalEmailIdentity::normalize($data['email']);
        Validator::make([...$data, 'name' => trim($data['name']), 'email' => $email], [
            'name' => ['required', 'string', 'max:160'], 'email' => ['required', 'email:rfc', 'max:254'],
            'password' => ['required', 'string', 'confirmed:passwordConfirmation', ...$this->passwordPolicy->rules()],
            'locale' => ['required', 'string', 'max:12', 'regex:/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/'], 'timezone' => ['required', 'timezone:all'],
        ])->validate();

        return ['name' => $data['name'], 'email' => $email, 'password' => $data['password'], 'locale' => $data['locale'], 'timezone' => $data['timezone'], 'extensions' => $data['extensions']];
    }
}
