<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\TestJoseBundle;

use SpomkyLabs\TestJoseBundle\DependencyInjection\TestExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

final class TestJoseBundle extends Bundle
{
    public function getContainerExtension()
    {
        return new TestExtension('jose_test');
    }
}
