<?php

declare(strict_types=1);
use Nvl\Support\Config\PackageEnvironment;

return ['routes' => [
    'enabled' => PackageEnvironment::get('NVL_AUTH_ROUTES_ENABLED', false),
    'prefix' => PackageEnvironment::get('NVL_AUTH_ROUTES_PREFIX', 'nvl/api/v1/auth'),
    'middleware' => ['api'],
    'public' => ['enabled' => false, 'middleware' => ['throttle:nvl.auth.public']],
    'account' => ['enabled' => false, 'middleware' => ['auth', 'throttle:nvl.auth.account']],
    'management' => ['enabled' => false, 'middleware' => ['auth', 'throttle:nvl.auth.management']],
]];
