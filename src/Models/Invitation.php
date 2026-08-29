<?php

declare(strict_types=1);

namespace Nvl\Auth\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Nvl\Auth\Database\Factories\InvitationFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\InvitationDeliveryStatus;

/**
 * Represents one bounded, bearer-token invitation.
 *
 * @property string $token_hash
 * @property string|null $active_key
 * @property string $recipient
 * @property string $recipient_hash
 * @property string|null $context_hash
 * @property string $type
 * @property string $purpose
 * @property string|null $inviter_type
 * @property string|null $inviter_id
 * @property string|null $accepted_by_type
 * @property string|null $accepted_by_id
 * @property list<string>|null $roles
 * @property list<string>|null $permissions
 * @property array<string, mixed>|null $metadata
 * @property int $resend_count
 * @property string|null $current_delivery_message_id
 * @property InvitationDeliveryStatus|null $delivery_status
 * @property CarbonImmutable|null $delivery_attempted_at
 * @property CarbonImmutable|null $delivered_at
 * @property CarbonImmutable|null $delivery_failed_at
 * @property string|null $delivery_failure_code
 * @property CarbonImmutable|null $last_sent_at
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $accepted_at
 * @property CarbonImmutable|null $revoked_at
 */
#[UseFactory(InvitationFactory::class)]
final class Invitation extends AuthModel
{
    public const TABLE = AuthTables::Invitations;

    /** @use HasFactory<InvitationFactory> */
    use HasFactory;

    /** @var string */
    protected $table = self::TABLE;

    /** @var list<string> */
    protected $fillable = [
        'token_hash',
        'active_key',
        'recipient',
        'recipient_hash',
        'context_hash',
        'type',
        'purpose',
        'inviter_type',
        'inviter_id',
        'accepted_by_type',
        'accepted_by_id',
        'roles',
        'permissions',
        'metadata',
        'resend_count',
        'current_delivery_message_id',
        'delivery_status',
        'delivery_attempted_at',
        'delivered_at',
        'delivery_failed_at',
        'delivery_failure_code',
        'last_sent_at',
        'expires_at',
        'accepted_at',
        'revoked_at',
    ];

    /** @var list<string> */
    protected $hidden = [
        'token_hash',
        'active_key',
        'recipient',
        'recipient_hash',
        'context_hash',
        'current_delivery_message_id',
    ];

    /**
     * Define invitation casts.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'recipient' => 'encrypted',
            'roles' => 'array',
            'permissions' => 'array',
            'metadata' => 'encrypted:array',
            'resend_count' => 'integer',
            'delivery_status' => InvitationDeliveryStatus::class,
            'delivery_attempted_at' => 'immutable_datetime',
            'delivered_at' => 'immutable_datetime',
            'delivery_failed_at' => 'immutable_datetime',
            'last_sent_at' => 'immutable_datetime',
            'expires_at' => 'immutable_datetime',
            'accepted_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }

    /**
     * Determine whether the invitation can still be consumed.
     */
    public function isUsable(): bool
    {
        return $this->accepted_at === null
            && $this->revoked_at === null
            && $this->expires_at->isFuture();
    }
}
