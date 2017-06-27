<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSetSource;

use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class PublicJWKSet extends AbstractJWKSetSource
{
    /**
     * {@inheritdoc}
     */
    public function createDefinition(ContainerBuilder $container, array $config)
    {
        $definition = new Definition('Jose\Component\Core\JWKSet');
        $definition->setFactory([
            new Reference('jose.factory.jwk'),
            'createPublicKeySet',
        ]);
        $definition->setArguments([new Reference($config['id'])]);

        return $definition;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeySet()
    {
        return 'public_jwkset';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
                ->scalarNode('id')
                    ->info('ID of the JWKSet to use.')
                    ->isRequired()
                ->end()
            ->end();
    }
}
