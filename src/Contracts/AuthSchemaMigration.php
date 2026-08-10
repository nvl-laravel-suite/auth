<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

/** Internal executable boundary shared by feature-aware Auth migrations. */
interface AuthSchemaMigration
{
    public function up(): void;

    public function down(): void;
}
