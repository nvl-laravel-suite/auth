<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\SocialIdentityFactory;

/**
 * Links one verified external provider identity to a host subject.
 *
 * @property string $subject_type
 * @property string $subject_id
 * @property string $provider
 * @property string $provider_user_id
 * @property string $provider_user_id_hash
 * @property string|null $email
 * @property array<string, mixed>|null $profile
 * @property CarbonImmutable|null $last_used_at
 * @property CarbonImmutable|null $revoked_at
 */
#[UseFactory(SocialIdentityFactory::class)]
final class SocialIdentity extends AuthModel
{
    public const TABLE = 'nvl_auth_social_identities';

    /** @use HasFactory<SocialIdentityFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'subject_type',
        'subject_id',
        'provider',
        'provider_user_id',
        'provider_user_id_hash',
        'email',
        'profile',
        'last_used_at',
        'revoked_at',
    ];

    /** @var list<string> */
    protected $hidden = ['provider_user_id', 'provider_user_id_hash', 'email', 'profile'];

    /**
     * Define social identity casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'provider_user_id' => 'encrypted',
            'email' => 'encrypted',
            'profile' => 'encrypted:array',
            'last_used_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }
}
