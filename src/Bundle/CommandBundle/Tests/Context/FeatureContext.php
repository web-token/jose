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

namespace SpomkyLabs\JoseBundle\Features\Context;

use Behat\Behat\Context\SnippetAcceptingContext;
use Behat\MinkExtension\Context\MinkContext;
use Behat\Symfony2Extension\Context\KernelDictionary;

/**
 * Behat context class.
 */
class FeatureContext extends MinkContext implements SnippetAcceptingContext
{
    use KernelDictionary;
    use LoaderContext;
    use VariableContext;
    use PayloadContext;
    use JWSCreationContext;
    use JWECreationContext;
    use KeysAndKeySetsContext;
    use JWTCreatorAndLoader;
    use ApplicationContext;
    use RequestContext;
    use ResponseContext;
}
