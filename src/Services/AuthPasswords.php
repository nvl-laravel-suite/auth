<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Passwords\DatabaseTokenRepository;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Auth\Passwords\PasswordBrokerManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\PasswordBroker as PasswordBrokerContract;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use Nvl\Support\Events\DomainEventDispatcher;
use SensitiveParameter;

/**
 * Complete native AuthPasswords operations.
 *
 * @api
 */
final readonly class AuthPasswords
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private AuthDeliveryContext $deliveryContext, private Hasher $hasher, private AuthAuditRecorder $audits, private AuthConfiguration $configuration, private PrincipalAttributeMapper $principalAttributes, private PasswordBrokerManager $brokers, private AuthPipeline $pipeline, private AuthenticationEligibility $eligibility, private DomainEventDispatcher $domainEvents, private PasswordUpdater $passwords, private ConnectionCommitCallbacks $eventCommits, private CanonicalActorResolver $canonical, private PasswordValidationRules $policy, private PrincipalSecurity $security, private RecentAuthenticationProofs $recent, private PrincipalEmailIdentity $emails) {}

    /**
     * Verify the current password and timestamp the active session.
     *
     * @param  array<string, mixed>  $data
     */
    public function confirm(
        Authenticatable $subject,
        #[SensitiveParameter]
        array $data,
        Session $session
    ): void {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $data = $this->validateConfirmPassword($data);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        if (! $subject instanceof Model) {
            throw AuthException::invalidConfiguration('Password confirmation requires an Eloquent principal.');
        }
        $prototype = new ($subject::class);
        $failedSubject = $prototype->getConnection()->transaction(function () use ($subject, $data, $session): ?Authenticatable {
            $this->security->assertTokenContainment($subject);
            $this->security->lock($subject);
            $this->security->lockChallenges($subject);
            $subject = $this->canonical->resolve($subject, true);
            $reference = SubjectReference::fromAuthenticatable($subject);
            if (! $this->hasher->check($data['password'], (string) $subject->getAuthPassword())) {
                return $subject;
            }
            $session->put('auth.password_confirmed_at', time());
            $this->audits->record('password.confirmed', subject: $reference, actor: $subject);

            return null;
        });
        if ($failedSubject !== null) {
            $this->audits->record('password.confirmation_failed', outcome: 'failure', subject: SubjectReference::fromAuthenticatable($failedSubject), actor: $failedSubject);
            throw new AuthException('password_invalid', 'The current password is invalid.', 422);
        }
    }

    /**
     * Request a reset without revealing whether the identifier exists.
     *
     * @param  array<string, mixed>  $data
     */
    public function requestReset(array $data, ?string $locale = null): void
    {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Issue);
        $data = $this->validateRequestPasswordReset($data);
        $identifierName = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $this->pipeline->run('password_reset_requested', new AuthPipelineContext('password_reset_requested', ['identifier_name' => $identifierName]), function () use ($data, $identifierName, $locale): void {
            $brokerName = $this->configuration->get('password_broker');
            $broker = $this->brokers->broker(is_string($brokerName) ? $brokerName : null);
            if (! $broker instanceof PasswordBroker) {
                throw new \LogicException('The configured password broker must use Laravel\'s password broker implementation.');
            }
            $subject = $broker->getUser($this->emails->brokerCredentials($identifierName, $data['identifier']));
            if (! $subject instanceof CanResetPassword) {
                $this->audits->record('password.reset_requested', metadata: ['matched' => false]);

                return;
            }
            if (! $subject instanceof Authenticatable) {
                $this->audits->record('password.reset_requested', metadata: ['matched' => false]);

                return;
            }
            $this->resetConnection($broker, $subject);
            $subject = $this->canonical->resolve($subject);
            if (! $subject instanceof CanResetPassword) {
                throw AuthException::invalidConfiguration('Password reset requires a resettable principal.');
            }
            try {
                $this->eligibility->assertEligible($subject, AuthenticationPurpose::PasswordReset);
            } catch (AuthException $exception) {
                $this->audits->record('password.reset_rejected', outcome: 'failure', subject: SubjectReference::fromAuthenticatable($subject), metadata: ['reason' => $exception->errorCode]);

                return;
            }
            $token = $broker->createToken($subject);
            $expiresAt = CarbonImmutable::now('UTC')->addMinutes($this->configuration->integerBetween('features.password.settings.reset_ttl_minutes', 60, 1, 10080));
            $this->domainEvents->dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(messageId: (string) Str::uuid(), feature: AuthFeature::Password, type: AuthMessageType::PasswordReset, recipient: $subject->getEmailForPasswordReset(), payload: ['token' => $token, 'identifier' => $data['identifier']], expiresAt: $expiresAt, locale: $locale), $this->deliveryContext->capture(true)), (new AuthAudit)->getConnection());
            $reference = SubjectReference::fromAuthenticatable($subject);
            $this->audits->record('password.reset_requested', subject: $reference, metadata: ['matched' => true]);
        });
    }

    /**
     * Reset a host-owned password through Laravel's broker.
     *
     * @param  array<string, mixed>  $data
     */
    public function reset(
        #[SensitiveParameter]
        array $data
    ): void {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $data = $this->validateResetPassword($data);
        $identifierName = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $status = $this->pipeline->run('password_reset', new AuthPipelineContext('password_reset', ['identifier_name' => $identifierName]), function () use ($data, $identifierName): string {
            $brokerName = $this->configuration->get('password_broker');
            $broker = $this->brokers->broker(is_string($brokerName) ? $brokerName : null);
            if (! $broker instanceof PasswordBroker) {
                throw AuthException::invalidConfiguration('Password reset requires Laravel’s password broker.');
            }
            $candidate = $broker->getUser($this->emails->brokerCredentials($identifierName, $data['identifier']));
            if ($candidate === null) {
                return PasswordBrokerContract::INVALID_USER;
            }
            if (! $candidate instanceof Authenticatable) {
                throw AuthException::invalidConfiguration('Atomic password reset requires an authenticatable principal.');
            }
            $connection = $this->resetConnection($broker, $candidate);
            $rejection = new class
            {
                public ?SubjectReference $subject = null;
            };
            try {
                $status = $connection->transaction(function () use ($broker, $candidate, $data, $identifierName, $rejection): string {
                    $this->security->assertTokenContainment($candidate);
                    $this->security->lock($candidate);
                    $this->security->lockChallenges($candidate);
                    $locked = $this->canonical->resolve($candidate, true);
                    if (! $locked instanceof CanResetPassword || ! $locked instanceof Model) {
                        throw AuthException::invalidConfiguration('Password reset requires a resettable Eloquent principal.');
                    }

                    return $broker->reset($this->emails->brokerCredentials($identifierName, $data['identifier']) + ['token' => $data['token'], 'password' => $data['password']], function (CanResetPassword $subject, #[SensitiveParameter] string $newPassword) use ($locked, $rejection): void {
                        if (! $subject instanceof Model || $subject::class !== $locked::class || ! $subject->is($locked)) {
                            throw AuthException::invalidConfiguration('Password broker returned a different principal.');
                        }
                        try {
                            $this->eligibility->assertEligible($locked, AuthenticationPurpose::PasswordReset);
                        } catch (AuthException $exception) {
                            $rejection->subject = SubjectReference::fromAuthenticatable($locked);
                            throw $exception;
                        }
                        $this->passwords->update($locked, $newPassword);
                        $locked->setRememberToken(Str::random(60));
                        $locked->save();
                        $this->security->advance($locked, 'password_reset');
                        $event = new PasswordReset($locked);
                        $this->eventCommits->afterCommit($locked->getConnection(), static function () use ($event): void {
                            event($event);
                        });
                        $this->audits->record('password.reset', subject: SubjectReference::fromAuthenticatable($locked));
                    });
                });
            } catch (AuthException $exception) {
                if ($rejection->subject !== null) {
                    $this->audits->record('password.reset_rejected', outcome: 'failure', subject: $rejection->subject, metadata: ['reason' => $exception->errorCode]);
                }
                throw $exception;
            }

            return $status;
        });
        if ($status !== PasswordBrokerContract::PASSWORD_RESET) {
            throw new AuthException('password_reset_invalid', 'The password reset token is invalid or expired.', 422);
        }
    }

    /** Require the broker, principal, and audit to share their actual transactional source. */
    private function resetConnection(PasswordBroker $broker, Authenticatable $candidate): ConnectionInterface
    {
        if (! $candidate instanceof Model) {
            throw AuthException::invalidConfiguration('Atomic password reset requires an Eloquent principal.');
        }
        $repository = $broker->getRepository();
        if ($repository::class !== DatabaseTokenRepository::class) {
            throw AuthException::invalidConfiguration('Atomic password reset requires a database token repository.');
        }
        try {
            $repositoryConnection = (new \ReflectionProperty(DatabaseTokenRepository::class, 'connection'))->getValue($repository);
        } catch (\ReflectionException) {
            throw AuthException::invalidConfiguration('Password reset token repository connection is unavailable.');
        }
        $prototype = new ($candidate::class);
        $connection = $prototype->getConnection();
        if (! $repositoryConnection instanceof ConnectionInterface || $repositoryConnection !== $connection || (new AuthAudit)->getConnection() !== $connection) {
            throw AuthException::invalidConfiguration('Password reset principal, token, and audit storage must share the same connection.');
        }

        return $connection;
    }

    /**
     * Verify and replace the current password.
     *
     * @param  array<string, mixed>  $data
     */
    public function update(
        Authenticatable&CanResetPassword $subject,
        #[SensitiveParameter]
        array $data, #[SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): void
    {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Update);
        $this->recent->assertValid($subject, $grant, RecentAuthenticationPurpose::PasswordChange, $context);
        $data = $this->validateUpdatePassword($data);
        if (! $subject instanceof Model) {
            throw AuthException::invalidConfiguration('Password updates require an Eloquent principal.');
        }
        $prototype = new ($subject::class);
        $prototype->getConnection()->transaction(function () use ($subject, $data, $grant, $context): void {
            $this->recent->consume($subject, $grant, RecentAuthenticationPurpose::PasswordChange, $context);
            $this->security->assertTokenContainment($subject);
            $this->security->lock($subject);
            $this->security->lockChallenges($subject);
            $subject = $this->canonical->resolve($subject, true);
            if (! $subject instanceof CanResetPassword) {
                throw AuthException::invalidConfiguration('Password updates require a resettable principal.');
            }
            $this->passwords->update($subject, $data['password']);
            $subject->setRememberToken(Str::random(60));
            $subject->save();
            $this->security->advance($subject, 'password_changed');
            $this->audits->record('password.updated', subject: SubjectReference::fromAuthenticatable($subject), actor: $subject);
        });
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{password: string}
     */
    private function validateConfirmPassword(#[SensitiveParameter] array $data): array
    {
        if (array_diff(array_keys($data), ['password']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['password'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [password].');
        }
        Validator::make($data, ['password' => ['required', 'string', 'max:4096']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{identifier: string}
     */
    private function validateRequestPasswordReset(array $data): array
    {
        if (array_diff(array_keys($data), ['identifier']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['identifier'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [identifier].');
        }
        Validator::make($data, ['identifier' => ['required', 'string', 'max:255']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{identifier: string, token: string, password: string, passwordConfirmation: string}
     */
    private function validateResetPassword(#[SensitiveParameter] array $data): array
    {
        if (array_diff(array_keys($data), ['identifier', 'token', 'password', 'passwordConfirmation']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['identifier'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [identifier].');
        }
        if (! is_string($data['token'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [token].');
        }
        if (! is_string($data['password'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [password].');
        }
        if (! is_string($data['passwordConfirmation'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [passwordConfirmation].');
        }
        Validator::make($data, ['identifier' => ['required', 'string', 'max:255'], 'token' => ['required', 'string', 'max:128'], 'password' => ['required', 'string', 'confirmed:passwordConfirmation', ...$this->policy->rules()]])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{password: string, passwordConfirmation: string}
     */
    private function validateUpdatePassword(#[SensitiveParameter] array $data): array
    {
        if (array_diff(array_keys($data), ['password', 'passwordConfirmation']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['password'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [password].');
        }
        if (! is_string($data['passwordConfirmation'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [passwordConfirmation].');
        }
        Validator::make($data, ['password' => ['required', 'string', 'confirmed:passwordConfirmation', ...$this->policy->rules()]])->validate();

        return $data;
    }
}
