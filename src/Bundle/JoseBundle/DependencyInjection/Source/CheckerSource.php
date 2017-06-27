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

final class CheckerSource implements SourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'checkers';
    }

    /**
     * {@inheritdoc}
     */
    public function createService($name, array $config, ContainerBuilder $container)
    {
        $service_id = sprintf('jose.checker.%s', $name);
        $definition = new Definition('Jose\Checker\CheckerManager');
        $definition->setFactory([
            new Reference('jose.factory.service'),
            'createChecker',
        ]);
        $definition->setArguments([
            $config['claims'],
            $config['headers'],
        ]);
        $definition->setPublic($config['is_public']);

        $container->setDefinition($service_id, $definition);
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode($this->getName())
                    ->useAttributeAsKey('name')
                    ->prototype('array')
                        ->children()
                            ->booleanNode('is_public')
                                ->info('If true, the service will be public, else private.')
                                ->defaultTrue()
                            ->end()
                            ->arrayNode('claims')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('headers')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->prototype('scalar')->end()
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
