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

    public const TABLE = 'nvl_auth_users';

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

    /** @var array<string, mixed> */
    protected $attributes = [
        'is_active' => true,
        'locale' => 'en',
        'timezone' => 'UTC',
    ];

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

    /**
     * Return the locale preferred by Laravel notifications and external consumers.
     */
    public function preferredLocale(): string
    {
        return $this->locale;
    }

    /**
     * Determine whether this principal may authenticate now.
     */
    public function isAuthenticationAllowed(): bool
    {
        return $this->is_active
            && $this->deleted_at === null
            && ($this->locked_until === null || $this->locked_until->isPast());
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
            ->where('is_active', true)
            ->where(static function (Builder $locks): void {
                $locks->whereNull('locked_until')->orWhere('locked_until', '<=', now());
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
            'email_verified_at' => 'immutable_datetime',
            'password' => 'hashed',
            'is_active' => 'boolean',
            'profile' => 'array',
            'preferences' => 'array',
            'last_login_at' => 'immutable_datetime',
            'last_login_ip' => 'encrypted',
            'locked_until' => 'immutable_datetime',
            'deleted_at' => 'immutable_datetime',
        ];
    }
}
