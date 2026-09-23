<?php

declare(strict_types=1);

namespace Nvl\Auth\Http;

/** Preserves snake-case HTTP input while accepting generated Data aliases. */
final class AuthRequestInput
{
    /**
     * @param  array<array-key, mixed>  $input
     * @param  array<string, list<string>>  $aliases
     * @return array<string, mixed>
     */
    public static function aliased(array $input, array $aliases): array
    {
        $normalized = [];

        foreach ($input as $key => $value) {
            if (is_string($key)) {
                $normalized[$key] = $value;
            }
        }

        foreach ($aliases as $target => $candidates) {
            if (array_key_exists($target, $normalized)) {
                continue;
            }

            foreach ($candidates as $candidate) {
                if (array_key_exists($candidate, $normalized)) {
                    $normalized[$target] = $normalized[$candidate];

                    break;
                }
            }
        }

        return $normalized;
    }
}
