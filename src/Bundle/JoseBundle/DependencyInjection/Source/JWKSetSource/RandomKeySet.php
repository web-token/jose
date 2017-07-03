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

use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class RandomKeySet extends AbstractJWKSetSource
{
    /**
     * {@inheritdoc}
     */
    public function createDefinition(ContainerBuilder $container, array $config)
    {
        if (true === $config['is_rotatable']) {
            $definition = new Definition('Jose\Object\RotatableJWKSet');
            $method = 'createRotatableKeySet';
        } else {
            $definition = new Definition('Jose\Object\StorableJWKSet');
            $method = 'createStorableKeySet';
        }

        $definition->setFactory([
            new Reference('jose.factory.jwk'),
            $method,
        ]);
        $definition->setArguments([
            $config['storage_path'],
            $config['key_configuration'],
            $config['nb_keys'],
        ]);

        return $definition;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeySet()
    {
        return 'auto';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
                ->booleanNode('is_rotatable')
                    ->info('If true, the service will be a rotatable key, else just storable.')
                    ->defaultFalse()
                ->end()
                ->integerNode('nb_keys')
                    ->info('Number of keys in the key set.')
                    ->isRequired()
                    ->min(1)
                ->end()
                ->scalarNode('storage_path')->isRequired()->end()
                ->arrayNode('key_configuration')
                    ->defaultValue([])
                    ->useAttributeAsKey('key')
                    ->prototype('variable')->end()
                ->end()
            ->end();
    }
}
