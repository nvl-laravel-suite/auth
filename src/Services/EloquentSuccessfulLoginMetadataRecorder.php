<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

/**
 * Stores package User login timestamps and optional client addresses.
 */
final class EloquentSuccessfulLoginMetadataRecorder implements SuccessfulLoginMetadataRecorder
{
    public function __construct(private readonly PrincipalAttributeMapper $attributes) {}

    /**
     * Record package-owned login metadata when the subject uses the package schema.
     */
    public function record(
        Authenticatable $subject,
        AuthenticationRequestContext $context,
    ): void {
        if (! $subject instanceof User) {
            return;
        }

        $metadata = [PrincipalAttribute::LastLoginAt->value => now()];

        if ($context->ipAddress !== null) {
            $metadata[PrincipalAttribute::LastLoginIp->value] = $context->ipAddress;
        }

        $subject->forceFill($this->attributes->map($metadata))->save();
    }
}
