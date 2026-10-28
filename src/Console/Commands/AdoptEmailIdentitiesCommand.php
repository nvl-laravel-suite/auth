<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Nvl\Auth\Services\PrincipalEmailIdentityAdoption;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Plans retained identity adoption; execution still requires the host system authorizer. */
final class AdoptEmailIdentitiesCommand extends Command
{
    protected $signature = 'nvl:auth:adopt-email-identities {--apply : Apply reviewed keys after draining legacy workers and disabling identity writes} {--reason= : Required reason for applying adoption} {--correlation= : Trace identifier}';

    protected $description = 'Inspect canonical email collisions or explicitly adopt retained keys';

    public function handle(PrincipalEmailIdentityAdoption $adoption): int
    {
        $result = $this->option('apply')
            ? $adoption->apply(new SystemMutationContext((string) $this->option('reason'), (string) ($this->option('correlation') ?: Str::uuid())))
            : $adoption->plan();
        $this->line((string) json_encode($result, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));

        return self::SUCCESS;
    }
}
