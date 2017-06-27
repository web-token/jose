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

use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;

abstract class AbstractSource
{
    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param array                                                   $config
     *
     * @return \Symfony\Component\DependencyInjection\Definition
     */
    abstract protected function createDefinition(ContainerBuilder $container, array $config);

    public function create(ContainerBuilder $container, $type, $name, array $config)
    {
        $service_id = sprintf('jose.%s.%s', $type, $name);
        $definition = $this->createDefinition($container, $config);
        $definition->setPublic($config['is_public']);
        $container->setDefinition($service_id, $definition);
    }

    /**
     * @param \Symfony\Component\Config\Definition\Builder\NodeDefinition $node
     */
    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
                ->booleanNode('is_public')
                    ->info('If true, the service will be public, else private.')
                    ->defaultTrue()
                ->end()
            ->end();
    }
}
