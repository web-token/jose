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

namespace Jose\Test\Context;

use Behat\Gherkin\Node\PyStringNode;
use Jose\Component\KeyManagement\JKUFactory;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Behat\Behat\Context\Context;
use Behat\Symfony2Extension\Context\KernelDictionary;

final class KeyContext implements Context
{
    use KernelDictionary;
    /**
     * @When I load a key set from an URI
     */
    public function iLoadAKeySetFromAnUri()
    {
        /** @var JKUFactory $jkuFactory */
        $jkuFactory = $this->getContainer()->get(JKUFactory::class);

        var_dump($jkuFactory->loadFromUrl('https://login.yahoo.com/openid/v1/certs'));
    }
}
