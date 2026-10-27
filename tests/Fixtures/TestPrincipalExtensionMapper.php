<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Contracts\PrincipalExtensionMapper;
use Nvl\Auth\Enums\PrincipalMutation;
use Nvl\Auth\Models\User;

/** Example host mapper using native arrays and presence-aware nullable fields. */
final class TestPrincipalExtensionMapper implements PrincipalExtensionMapper
{
    public function validateAndMap(PrincipalMutation $mutation, #[\SensitiveParameter] array $extensions, ?User $principal = null): array
    {
        if (array_diff(array_keys($extensions), ['jobTitle', 'phone']) !== []) {
            throw new \InvalidArgumentException('Unknown principal extension.');
        }
        $validated = Validator::make($extensions, [
            'jobTitle' => ['sometimes', 'nullable', 'string', 'max:100'],
            'phone' => ['sometimes', 'nullable', 'string', 'max:30'],
        ])->validate();
        $mapped = [];
        foreach (['jobTitle' => 'job_title', 'phone' => 'phone'] as $logical => $column) {
            if (array_key_exists($logical, $validated)) {
                $mapped[$column] = $validated[$logical];
            }
        }

        return $mapped;
    }
}
