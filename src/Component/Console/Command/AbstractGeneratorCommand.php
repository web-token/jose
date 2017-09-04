<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Console\Command;

use Jose\Component\Core\JWKFactory;
use Symfony\Component\Console\Command\Command;

abstract class AbstractGeneratorCommand extends Command
{
    /**
     * {@inheritdoc}
     */
    public function isEnabled()
    {
        return class_exists(JWKFactory::class);
    }
}
