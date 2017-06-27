<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\DependencyInjection\Source;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class JWTLoaderSource implements SourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'jwt_loaders';
    }

    /**
     * {@inheritdoc}
     */
    public function createService($name, array $config, ContainerBuilder $container)
    {
        $service_id = sprintf('jose.jwt_loader.%s', $name);
        $definition = new Definition('Jose\JWTLoader');
        $definition->setFactory([
            new Reference('jose.factory.service'),
            'createJWTLoader',
        ]);
        $definition->setArguments([
            new Reference($config['checker']),
            new Reference($config['verifier']),
            null === $config['decrypter'] ? null : new Reference($config['decrypter']),
        ]);
        $definition->setPublic($config['is_public']);

        $container->setDefinition($service_id, $definition);
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $node->children()
                ->arrayNode($this->getName())
                    ->useAttributeAsKey('name')
                    ->prototype('array')
                        ->children()
                            ->booleanNode('is_public')
                                ->info('If true, the service will be public, else private.')
                                ->defaultTrue()
                            ->end()
                            ->scalarNode('verifier')
                                ->isRequired()
                            ->end()
                            ->scalarNode('checker')
                                ->isRequired()
                            ->end()
                            ->scalarNode('decrypter')
                                ->defaultNull()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config)
    {
    }
}
