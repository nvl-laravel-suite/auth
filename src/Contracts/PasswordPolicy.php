<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Validation\Rules\Password;

/** Consumer-replaceable policy for new passwords. */
interface PasswordPolicy
{
    /** @return list<string|ValidationRule|Password> */
    public function rules(): array;
}
