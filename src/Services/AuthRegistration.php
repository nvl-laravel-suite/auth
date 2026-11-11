<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
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
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\User;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Support\UniqueViolation;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\IssuedSocialRegistration;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\DomainEventDispatcher;

/**
 * Completes native password signup; the consumer commits before authenticating.
 *
 * @api
 */
final readonly class AuthRegistration
{
    public function __construct(private AuthModelRegistry $models, private ConfiguredRegistrationAdmission $nativeAdmission, private RegistrationAdmission $admission, private PrincipalExtensions $extensions, private PrincipalAttributeMapper $attributes, private PasswordValidationRules $passwordPolicy, private PasswordUpdater $passwords, private FeatureGate $features, private AuthConfiguration $configuration, private AuthOperationBoundary $operations, private PrincipalSecurity $security, private AuthCommittedAudit $audits, private DomainEventDispatcher $events, private AuthEmailVerification $verification, private AuthPipeline $pipeline, private SocialRegistrationContinuations $social, private SecretHasher $hasher, private AuthIdentityChallenges $records) {}

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
                    // The savepoint keeps the source transaction usable for reading which index was violated.
                    $user = $connection->transaction(static fn (): User => $class::query()->create($mapped + $extensions));
                } catch (UniqueConstraintViolationException $exception) {
                    if (UniqueViolation::columns($exception, $connection, (new $class)->getTable()) === null) {
                        throw $exception;
                    }
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

    /** @param array<string, mixed> $data */
    public function registerSocial(#[\SensitiveParameter] string $continuation, array $data, AuthenticationRequestContext $context): User
    {
        return $this->provisionSocial($continuation, $data, $context);
    }

    /** A real invitation token and a proved matching mailbox are both mandatory.
     * @param  array<string, mixed>  $data
     * @return array{invitation: Invitation, subject: User}
     */
    public function registerInvitedSocial(#[\SensitiveParameter] string $invitationToken, #[\SensitiveParameter] string $continuation, array $data, AuthenticationRequestContext $context): array
    {
        $invitations = app(AuthInvitations::class);
        $invitation = $invitations->preview($invitationToken);
        if ($invitation->getConnection() !== (new Challenge)->getConnection()) {
            throw AuthException::invalidConfiguration('Invited signup requires one source.');
        }

        return $invitation->getConnection()->transaction(function () use ($invitations, $invitationToken, $invitation, $continuation, $data, $context): array {
            $user = $this->provisionSocial($continuation, $data, $context, $invitation->recipient);

            return ['invitation' => $invitations->accept($invitationToken, $user), 'subject' => $user];
        });
    }

    public function requestSocialEmailVerification(#[\SensitiveParameter] string $continuation, string $email, AuthenticationRequestContext $context): void
    {
        $this->nativeAdmission->assertProvisioningAllowed(true, RegistrationMethod::Social);
        $this->social->request($continuation, $email, $context);
    }

    public function verifySocialEmail(#[\SensitiveParameter] string $continuation, #[\SensitiveParameter] string $code, AuthenticationRequestContext $context): IssuedSocialRegistration
    {
        return $this->social->verify($continuation, $code, $context);
    }

    /** @param array<string, mixed> $data */
    private function provisionSocial(#[\SensitiveParameter] string $continuation, array $data, AuthenticationRequestContext $context, ?string $invitedEmail = null): User
    {
        $this->nativeAdmission->assertProvisioningAllowed($invitedEmail !== null, RegistrationMethod::Social);
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Enroll);
        if (array_diff(array_keys($data), ['name', 'locale', 'timezone', 'extensions']) !== []) {
            throw new InvalidArgumentException('Unknown social registration fields.');
        }
        $data += ['locale' => 'en', 'timezone' => 'UTC', 'extensions' => []];
        if (! is_string($data['name'] ?? null) || ! is_string($data['locale']) || ! is_string($data['timezone']) || ! is_array($data['extensions'])) {
            throw new InvalidArgumentException('Invalid social signup data.');
        }
        Validator::make($data, ['name' => ['required', 'string', 'max:160'], 'locale' => ['required', 'string', 'max:12'], 'timezone' => ['required', 'timezone:all'], 'extensions' => ['array']])->validate();
        $class = $this->models->userClass();
        $prototype = new $class;
        PrincipalEmailIdentity::assertReady($prototype);
        $connection = $prototype->getConnection();
        if ($connection !== (new Challenge)->getConnection() || $connection !== (new SocialIdentity)->getConnection() || $connection !== (new AuthAudit)->getConnection()) {
            throw AuthException::invalidConfiguration('Social signup requires one source.');
        }
        try {
            return $connection->transaction(function () use ($continuation, $context, $data, $class, $connection, $invitedEmail): User {
                $proof = $this->social->lock($continuation, $context);
                $claims = $this->social->claims($proof);
                $email = $proof->payload['mailbox'] ?? ($claims['emailVerified'] === true ? $claims['email'] : null);
                if (! is_string($email)) {
                    throw new AuthException('social_registration_mailbox_required', 'Verify a signup mailbox before registration.', 422);
                }
                $email = PrincipalEmailIdentity::normalize($email);
                Validator::make(['email' => $email], ['email' => ['required', 'email:rfc', 'max:254']])->validate();
                if ($invitedEmail !== null && $email !== PrincipalEmailIdentity::normalize($invitedEmail)) {
                    throw new AuthException('invitation_recipient_mismatch', 'The verified signup mailbox must match the invitation.', 422);
                }

                return $this->pipeline->run('registration', new AuthPipelineContext('registration', ['method' => 'social', 'attributes' => array_keys($data)]), function () use ($proof, $claims, $email, $data, $class, $connection, $invitedEmail): User {
                    $mapped = $this->attributes->map(['name' => $data['name'], 'email' => $email, 'active' => true, 'emailVerified' => true, 'locale' => $data['locale'], 'timezone' => $data['timezone'], 'profile' => [], 'preferences' => []]);
                    $extensions = $this->extensions->map(PrincipalMutation::Registration, $data['extensions'], occupiedColumns: array_keys($mapped));
                    $this->admission->assertAllowed(RegistrationMethod::Social, $email, $extensions);
                    $this->nativeAdmission->assertProvisioningAllowed($invitedEmail !== null, RegistrationMethod::Social);
                    $hash = $this->hasher->hash('social-identity-'.$claims['provider'], $claims['id']);
                    if (SocialIdentity::query()->where('provider', $claims['provider'])->where('provider_user_id_hash', $hash)->exists()) {
                        throw new AuthException('registration_unavailable', 'Registration is unavailable.', 409);
                    }
                    $user = $class::query()->create($mapped + $extensions);
                    $reference = SubjectReference::fromAuthenticatable($user);
                    $this->security->lock($user);
                    SocialIdentity::query()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'provider' => $claims['provider'], 'provider_user_id' => $claims['id'], 'provider_user_id_hash' => $hash, 'email' => $claims['email'], 'profile' => ['issuer' => $claims['issuer'], 'email_verified' => $claims['emailVerified'], 'email_verification_source' => $claims['source'], 'connection_realm' => $this->configuration->get('features.social_identities.settings.providers.'.$claims['provider'].'.realm')], 'last_used_at' => now()]);
                    $proof->consumed_at = CarbonImmutable::now();
                    $this->records->save($proof);
                    $this->audits->record($connection, 'registration.completed', subject: $reference, metadata: ['method' => 'social']);
                    $this->events->dispatch(new PrincipalRegistered($reference, RegistrationMethod::Social), $connection);

                    return $user->refresh();
                });
            }, 3);
        } catch (UniqueConstraintViolationException $exception) {
            if (UniqueViolation::columns($exception, $connection, (new $class)->getTable()) === null && UniqueViolation::columns($exception, $connection, (new SocialIdentity)->getTable()) === null) {
                throw $exception;
            }
            throw new AuthException('registration_unavailable', 'Registration is unavailable.', 409, previous: $exception);
        }
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
