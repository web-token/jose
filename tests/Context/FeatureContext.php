<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Context;

use Behat\Behat\Context\Context;
use Behat\Symfony2Extension\Context\KernelDictionary;
use Jose\Component\Encryption\Compression\CompressionMethodsManagerFactory;

/**
 * Behat context class.
 */
final class FeatureContext implements Context
{
    use KernelDictionary;

    /**
     * @Given the compression methods manager factory is available
     */
    public function theCompressionMethodsManagerFactoryIsAvailable()
    {
        var_dump($this->getContainer()->has(CompressionMethodsManagerFactory::class));
    }
}
