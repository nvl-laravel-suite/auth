<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Closure;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Validation\Rules\Password;
use Nvl\Auth\Contracts\PasswordPolicy;

/** Combines host policy with mandatory bounded input and hash-engine safety. */
final readonly class PasswordValidationRules
{
    public function __construct(private PasswordPolicy $policy, private Hasher $hasher) {}

    /** @return list<string|ValidationRule|Password> */
    public function rules(): array
    {
        $rules = ['max:4096', ...$this->policy->rules()];
        if ($this->hasher instanceof BcryptHasher) {
            $rules[] = new class implements ValidationRule
            {
                public function validate(string $attribute, #[\SensitiveParameter] mixed $value, Closure $fail): void
                {
                    if (is_string($value) && strlen($value) > 72) {
                        $fail('The :attribute may not exceed 72 bytes.');
                    }
                }
            };
        }

        return $rules;
    }
}
