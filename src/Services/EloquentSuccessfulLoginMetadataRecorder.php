<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

/**
 * Stores package User login timestamps and optional client addresses.
 */
final class EloquentSuccessfulLoginMetadataRecorder implements SuccessfulLoginMetadataRecorder
{
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

        $metadata = ['last_login_at' => now()];

        if ($context->ipAddress !== null) {
            $metadata['last_login_ip'] = $context->ipAddress;
        }

        $subject->forceFill($metadata)->save();
    }
}
