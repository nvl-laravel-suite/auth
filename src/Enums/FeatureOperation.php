<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Describes the lifecycle operation requested from an Auth feature.
 */
enum FeatureOperation: string
{
    case Read = 'read';
    case Enroll = 'enroll';
    case Issue = 'issue';
    case Use = 'use';
    case Update = 'update';
    case Revoke = 'revoke';
    case Cleanup = 'cleanup';

    /**
     * Determine whether the operation is a containment operation.
     */
    public function isContainment(): bool
    {
        return $this === self::Revoke || $this === self::Cleanup;
    }
}
