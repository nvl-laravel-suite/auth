<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Auth\MustVerifyEmail;
use Illuminate\Auth\Passwords\CanResetPassword;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordContract;
use Illuminate\Contracts\Auth\MustVerifyEmail as MustVerifyEmailContract;
use Illuminate\Contracts\Translation\HasLocalePreference;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\Contracts\HasApiTokens as HasApiTokensContract;
use Laravel\Sanctum\HasApiTokens;
use Nvl\Auth\Database\Factories\UserFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\PrincipalAttribute;
use Spatie\Permission\Traits\HasRoles;

/**
 * Provides the package's complete, extensible default authentication principal.
 *
 * Consumer applications may extend this class to add application relationships
 * while preserving the package-owned identity and authentication contracts.
 *
 * @property string $id
 * @property string $name
 * @property string $email
 * @property CarbonImmutable|null $email_verified_at
 * @property string|null $password
 * @property bool $is_active
 * @property string $locale
 * @property string $timezone
 * @property array<string, mixed>|null $profile
 * @property array<string, mixed>|null $preferences
 * @property CarbonImmutable|null $last_login_at
 * @property string|null $last_login_ip
 * @property CarbonImmutable|null $locked_until
 * @property string|null $remember_token
 * @property CarbonImmutable|null $deleted_at
 */
#[UseFactory(UserFactory::class)]
class User extends Authenticatable implements CanResetPasswordContract, HasApiTokensContract, HasLocalePreference, MustVerifyEmailContract
{
    use CanResetPassword;
    use HasApiTokens;

    /** @use HasFactory<UserFactory> */
    use HasFactory;

    use HasRoles;
    use HasUuids;
    use MustVerifyEmail;
    use Notifiable;
    use SoftDeletes;

    public const TABLE = AuthTables::Users;

    /** @var string */
    protected $table = self::TABLE;

    /** @var string */
    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = [
        'name',
        'email',
        'email_verified_at',
        'password',
        'is_active',
        'locale',
        'timezone',
        'profile',
        'preferences',
        'last_login_at',
        'last_login_ip',
        'locked_until',
    ];

    /** @var list<string> */
    protected $hidden = [
        'password',
        'remember_token',
        'last_login_ip',
    ];

    /**
     * Create a principal with defaults aligned to the configured field map.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        $this->attributes = [
            $this->principalColumn(PrincipalAttribute::Active) => true,
            $this->principalColumn(PrincipalAttribute::Locale) => 'en',
            $this->principalColumn(PrincipalAttribute::Timezone) => 'UTC',
        ];

        parent::__construct($attributes);
    }

    /**
     * Resolve mass-assignable fields through the configured principal map.
     *
     * @return list<string>
     */
    public function getFillable(): array
    {
        return array_map($this->principalColumn(...), [
            PrincipalAttribute::Name,
            PrincipalAttribute::Email,
            PrincipalAttribute::EmailVerifiedAt,
            PrincipalAttribute::Password,
            PrincipalAttribute::Active,
            PrincipalAttribute::Locale,
            PrincipalAttribute::Timezone,
            PrincipalAttribute::Profile,
            PrincipalAttribute::Preferences,
            PrincipalAttribute::LastLoginAt,
            PrincipalAttribute::LastLoginIp,
            PrincipalAttribute::LockedUntil,
        ]);
    }

    /**
     * Resolve hidden fields through the configured principal map.
     *
     * @return list<string>
     */
    public function getHidden(): array
    {
        return array_map($this->principalColumn(...), [
            PrincipalAttribute::Password,
            PrincipalAttribute::RememberToken,
            PrincipalAttribute::LastLoginIp,
        ]);
    }

    /**
     * Resolve the configured package table without preventing model extension.
     */
    public function getTable(): string
    {
        $configured = config('nvl-auth.tables.users');

        return is_string($configured) && trim($configured) !== ''
            ? trim($configured)
            : parent::getTable();
    }

    /**
     * Resolve the immutable package operational connection.
     */
    public function getConnectionName(): ?string
    {
        $configured = config('nvl-auth.connection');

        return is_string($configured) && trim($configured) !== ''
            ? trim($configured)
            : parent::getConnectionName();
    }

    public function getKeyName(): string
    {
        return $this->principalColumn(PrincipalAttribute::Id);
    }

    public function getAuthPasswordName(): string
    {
        return $this->principalColumn(PrincipalAttribute::Password);
    }

    public function getEmailForVerification(): string
    {
        $email = $this->getAttribute($this->principalColumn(PrincipalAttribute::Email));

        return is_string($email) ? $email : '';
    }

    public function getEmailForPasswordReset(): string
    {
        return $this->getEmailForVerification();
    }

    public function hasVerifiedEmail(): bool
    {
        return $this->getAttribute(
            $this->principalColumn(PrincipalAttribute::EmailVerifiedAt),
        ) !== null;
    }

    public function markEmailAsVerified(): bool
    {
        return $this->forceFill([
            $this->principalColumn(PrincipalAttribute::EmailVerifiedAt) => $this->freshTimestamp(),
        ])->save();
    }

    public function getRememberTokenName(): string
    {
        return $this->principalColumn(PrincipalAttribute::RememberToken);
    }

    public function getCreatedAtColumn(): ?string
    {
        return $this->principalColumn(PrincipalAttribute::CreatedAt);
    }

    public function getUpdatedAtColumn(): ?string
    {
        return $this->principalColumn(PrincipalAttribute::UpdatedAt);
    }

    public function getDeletedAtColumn(): string
    {
        return $this->principalColumn(PrincipalAttribute::DeletedAt);
    }

    /**
     * Return the locale preferred by Laravel notifications and external consumers.
     */
    public function preferredLocale(): string
    {
        $locale = $this->getAttribute($this->principalColumn(PrincipalAttribute::Locale));

        return is_string($locale) && $locale !== '' ? $locale : 'en';
    }

    /**
     * Determine whether this principal may authenticate now.
     */
    public function isAuthenticationAllowed(): bool
    {
        $active = $this->getAttribute($this->principalColumn(PrincipalAttribute::Active));
        $deletedAt = $this->getAttribute($this->principalColumn(PrincipalAttribute::DeletedAt));
        $lockedUntil = $this->getAttribute($this->principalColumn(PrincipalAttribute::LockedUntil));

        return (bool) $active
            && $deletedAt === null
            && ($lockedUntil === null
                || ($lockedUntil instanceof CarbonImmutable && $lockedUntil->isPast()));
    }

    /**
     * Constrain a query to principals eligible to authenticate.
     *
     * @param  Builder<User>  $query
     * @return Builder<User>
     */
    public function scopeAuthenticationAllowed(Builder $query): Builder
    {
        return $query
            ->where($this->principalColumn(PrincipalAttribute::Active), true)
            ->where(function (Builder $locks): void {
                $lockedUntil = $this->principalColumn(PrincipalAttribute::LockedUntil);
                $locks->whereNull($lockedUntil)->orWhere($lockedUntil, '<=', now());
            });
    }

    /** @return MorphMany<Challenge, $this> */
    public function authChallenges(): MorphMany
    {
        return $this->morphMany(Challenge::class, 'subject');
    }

    /** @return MorphMany<TotpCredential, $this> */
    public function totpCredentials(): MorphMany
    {
        return $this->morphMany(TotpCredential::class, 'subject');
    }

    /** @return MorphMany<Passkey, $this> */
    public function passkeys(): MorphMany
    {
        return $this->morphMany(Passkey::class, 'subject');
    }

    /** @return MorphMany<RecoveryCode, $this> */
    public function recoveryCodes(): MorphMany
    {
        return $this->morphMany(RecoveryCode::class, 'subject');
    }

    /** @return MorphMany<SocialIdentity, $this> */
    public function socialIdentities(): MorphMany
    {
        return $this->morphMany(SocialIdentity::class, 'subject');
    }

    /** @return MorphMany<AuthClientSession, $this> */
    public function authClientSessions(): MorphMany
    {
        return $this->morphMany(AuthClientSession::class, 'subject');
    }

    /** @return MorphMany<Invitation, $this> */
    public function sentInvitations(): MorphMany
    {
        return $this->morphMany(Invitation::class, 'inviter');
    }

    /** @return MorphMany<Invitation, $this> */
    public function acceptedInvitations(): MorphMany
    {
        return $this->morphMany(Invitation::class, 'accepted_by');
    }

    /** @return MorphMany<AuthAudit, $this> */
    public function authAudits(): MorphMany
    {
        return $this->morphMany(AuthAudit::class, 'subject');
    }

    /** @return MorphMany<AuthAudit, $this> */
    public function performedAuthAudits(): MorphMany
    {
        return $this->morphMany(AuthAudit::class, 'actor');
    }

    /**
     * Define principal casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            $this->principalColumn(PrincipalAttribute::EmailVerifiedAt) => 'immutable_datetime',
            $this->principalColumn(PrincipalAttribute::Password) => 'hashed',
            $this->principalColumn(PrincipalAttribute::Active) => 'boolean',
            $this->principalColumn(PrincipalAttribute::Profile) => 'array',
            $this->principalColumn(PrincipalAttribute::Preferences) => 'array',
            $this->principalColumn(PrincipalAttribute::LastLoginAt) => 'immutable_datetime',
            $this->principalColumn(PrincipalAttribute::LastLoginIp) => 'encrypted',
            $this->principalColumn(PrincipalAttribute::LockedUntil) => 'immutable_datetime',
            $this->principalColumn(PrincipalAttribute::DeletedAt) => 'immutable_datetime',
        ];
    }

    private function principalColumn(PrincipalAttribute $attribute): string
    {
        $configured = config(
            "nvl-auth.features.principal_management.settings.attributes.{$attribute->value}",
            $attribute === PrincipalAttribute::Active ? 'is_active' : $attribute->value,
        );

        return is_string($configured) && $configured !== ''
            ? $configured
            : ($attribute === PrincipalAttribute::Active ? 'is_active' : $attribute->value);
    }
}
