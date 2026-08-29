<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Identifies supported Auth consumer integration presets.
 */
enum AuthIntegrationPreset: string
{
    case EmbeddedApplication = 'embedded-application';
}
