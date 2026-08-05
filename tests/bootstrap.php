<?php

declare(strict_types=1);

$autoload = dirname(__DIR__, 4).'/vendor/autoload.php';

if (! is_file($autoload)) {
    throw new RuntimeException('Run Composer install from the monorepo root before testing nvl/auth.');
}

require $autoload;

require __DIR__.'/Pest.php';
