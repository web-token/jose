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

namespace SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSetSource;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class X5U extends DownloadedJWKSet
{
    /**
     * {@inheritdoc}
     */
    public function createDefinition(ContainerBuilder $container, array $config)
    {
        $definition = new Definition('Jose\Object\X5UJWKSet');
        $definition->setFactory([
            new Reference('jose.factory.jwk'),
            'createFromX5U',
        ]);
        $definition->setArguments([
            $config['url'],
            $config['is_secured'],
            $config['cache'],
            $config['cache_ttl'],
            $config['is_https'],
        ]);

        return $definition;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeySet()
    {
        return 'x5u';
    }
}
