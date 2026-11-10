<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Client, flow, and return destination for starting authentication.
 *
 * @api
 */
final class StartClientAuthData
{
    public function __construct(
        public readonly string $clientId,
        public readonly string $flow,
        public readonly string $returnPath,
        public readonly ?string $origin = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'origin' => ['sometimes', 'nullable', 'string'],
            'clientId' => ['required', 'string', 'max:191'],
            'flow' => ['required', 'string'],
            'returnPath' => ['required', 'string'],
        ];
    }
}
