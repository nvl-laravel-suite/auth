<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Auth\Passwords\PasswordBrokerManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\PasswordBroker as PasswordBrokerContract;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Session\Session;
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
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use Nvl\Support\Events\DomainEventDispatcher;
use SensitiveParameter;

/** Complete native AuthPasswords operations.
 * @api
 */
final readonly class AuthPasswords
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private AuthDeliveryContext $deliveryContext, private Hasher $hasher, private AuthAuditRecorder $audits, private AuthConfiguration $configuration, private PrincipalAttributeMapper $principalAttributes, private PasswordBrokerManager $brokers, private AuthPipeline $pipeline, private AuthenticationEligibility $eligibility, private DomainEventDispatcher $domainEvents, private PasswordUpdater $passwords, private ConnectionCommitCallbacks $eventCommits) {}

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
        $reference = SubjectReference::fromAuthenticatable($subject);
        if (! $this->hasher->check($data['password'], (string) $subject->getAuthPassword())) {
            $this->audits->record('password.confirmation_failed', outcome: 'failure', subject: $reference, actor: $subject);
            throw new AuthException('password_invalid', 'The current password is invalid.', 422);
        }
        $session->put('auth.password_confirmed_at', time());
        $this->audits->record('password.confirmed', subject: $reference, actor: $subject);
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
            $subject = $broker->getUser([$identifierName => $data['identifier']]);
            if (! $subject instanceof CanResetPassword) {
                $this->audits->record('password.reset_requested', metadata: ['matched' => false]);

                return;
            }
            if (! $subject instanceof Authenticatable) {
                $this->audits->record('password.reset_requested', metadata: ['matched' => false]);

                return;
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
            $status = $broker->reset([$identifierName => $data['identifier'], 'token' => $data['token'], 'password' => $data['password']], function (CanResetPassword $subject, string $newPassword): void {
                if (! $subject instanceof Authenticatable) {
                    throw AuthException::invalidConfiguration('Password reset subjects must implement Laravel Authenticatable.');
                }
                try {
                    $this->eligibility->assertEligible($subject, AuthenticationPurpose::PasswordReset);
                } catch (AuthException $exception) {
                    $this->audits->record('password.reset_rejected', outcome: 'failure', subject: SubjectReference::fromAuthenticatable($subject), metadata: ['reason' => $exception->errorCode]);
                    throw $exception;
                }
                $update = function () use ($subject, $newPassword): void {
                    $this->passwords->update($subject, $newPassword);
                    $event = new PasswordReset($subject);
                    if ($this->passwords instanceof EloquentPasswordUpdater && $subject instanceof Model) {
                        $this->eventCommits->afterCommit($subject->getConnection(), static function () use ($event): void {
                            event($event);
                        });
                    } else {
                        event($event);
                    }
                    $this->audits->record('password.reset', subject: SubjectReference::fromAuthenticatable($subject));
                };
                if ($this->passwords instanceof EloquentPasswordUpdater && $subject instanceof Model) {
                    $subject->getConnection()->transaction($update);
                } else {
                    $update();
                }
            });
            if (! is_string($status)) {
                throw AuthException::invalidConfiguration('Laravel password broker returned an invalid status.');
            }

            return $status;
        });
        if ($status !== PasswordBrokerContract::PASSWORD_RESET) {
            throw new AuthException('password_reset_invalid', 'The password reset token is invalid or expired.', 422);
        }
    }

    /**
     * Verify and replace the current password.
     *
     * @param  array<string, mixed>  $data
     */
    public function update(
        Authenticatable&CanResetPassword $subject,
        #[SensitiveParameter]
        array $data
    ): void {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Update);
        $data = $this->validateUpdatePassword($data);
        if (! $this->hasher->check($data['currentPassword'], (string) $subject->getAuthPassword())) {
            throw new AuthException('password_invalid', 'The current password is invalid.', 422);
        }
        $this->passwords->update($subject, $data['password']);
        $this->audits->record('password.updated', subject: SubjectReference::fromAuthenticatable($subject), actor: $subject);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{password: string}
     */
    private function validateConfirmPassword(array $data): array
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
    private function validateResetPassword(array $data): array
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
        Validator::make($data, ['identifier' => ['required', 'string', 'max:255'], 'token' => ['required', 'string', 'max:128'], 'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed:passwordConfirmation']])->validate();

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{currentPassword: string, password: string, passwordConfirmation: string}
     */
    private function validateUpdatePassword(array $data): array
    {
        if (array_diff(array_keys($data), ['currentPassword', 'password', 'passwordConfirmation']) !== []) {
            throw new \InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['currentPassword'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [currentPassword].');
        }
        if (! is_string($data['password'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [password].');
        }
        if (! is_string($data['passwordConfirmation'] ?? null)) {
            throw new \InvalidArgumentException('Invalid Auth input [passwordConfirmation].');
        }
        Validator::make($data, ['currentPassword' => ['required', 'string', 'max:4096'], 'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed:passwordConfirmation']])->validate();

        return $data;
    }
}
