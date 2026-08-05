<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use LogicException;

/**
 * Converts Laravel-validated request values into explicit transport types.
 */
trait InteractsWithValidatedInput
{
    /**
     * Return request input with string keys for DTO validation.
     *
     * @return array<string, mixed>
     */
    protected function requestPayload(Request $request): array
    {
        $payload = [];

        foreach ($request->all() as $key => $value) {
            if (is_string($key)) {
                $payload[$key] = $value;
            }
        }

        return $payload;
    }

    /**
     * Return one required validated string.
     */
    protected function stringInput(Request $request, string $key): string
    {
        $value = $request->input($key);

        if (! is_string($value)) {
            throw new LogicException("The validated [{$key}] input must be a string.");
        }

        return $value;
    }

    /**
     * Return one optional validated string.
     */
    protected function optionalStringInput(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw new LogicException("The validated [{$key}] input must be a string or null.");
        }

        return $value;
    }

    /**
     * Return a validated list containing only strings.
     *
     * @param  list<string>  $default
     * @return list<string>
     */
    protected function stringListInput(Request $request, string $key, array $default = []): array
    {
        $value = $request->input($key, $default);

        if (! is_array($value)) {
            throw new LogicException("The validated [{$key}] input must be an array.");
        }

        $strings = [];

        foreach ($value as $item) {
            if (! is_string($item)) {
                throw new LogicException("Every validated [{$key}] value must be a string.");
            }

            $strings[] = $item;
        }

        return $strings;
    }

    /**
     * Return one validated associative payload.
     *
     * @param  array<string, mixed>  $default
     * @return array<string, mixed>
     */
    protected function associativeInput(Request $request, string $key, array $default = []): array
    {
        $value = $request->input($key, $default);

        if (! is_array($value)) {
            throw new LogicException("The validated [{$key}] input must be an array.");
        }

        $payload = [];

        foreach ($value as $payloadKey => $item) {
            if (! is_string($payloadKey)) {
                throw new LogicException("Every validated [{$key}] key must be a string.");
            }

            $payload[$payloadKey] = $item;
        }

        return $payload;
    }
}
