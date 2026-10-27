<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Validation\Rules\Password;
use Nvl\Auth\Contracts\PasswordPolicy;

/** Default policy for new passwords. */
final readonly class ConfiguredPasswordPolicy implements PasswordPolicy
{
    public function rules(): array
    {
        return [Password::min(12)];
    }
}
