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

use SpomkyLabs\JoseBundle\DependencyInjection\Source\AbstractSource;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

abstract class AbstractJWKSetSource extends AbstractSource implements JWKSetSourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function create(ContainerBuilder $container, $type, $name, array $config)
    {
        parent::create($container, $type, $name, $config);

        if (null !== $config['path']) {
            $jwkset_id = 'jose.key_set.'.$name;
            $controller_definition = new Definition('SpomkyLabs\JoseBundle\Controller\JWKSetController');
            $controller_definition->setFactory([new Reference('jose.controller.jwkset_controllery_factory'), 'createJWKSetController']);
            $controller_definition->setArguments([new Reference($jwkset_id)]);
            $controller_id = 'jose.controller.'.$name;
            $container->setDefinition($controller_id, $controller_definition);

            $jwkset_loader_definition = $container->getDefinition('jose.routing.jwkset_loader');
            $jwkset_loader_definition->addMethodCall('addJWKSetRoute', [$config['path'], $name]);
        }
    }

    /**
     * @param \Symfony\Component\Config\Definition\Builder\NodeDefinition $node
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
                ->scalarNode('path')
                    ->info('To share the JWKSet, then set a valid path (e.g. "/jwkset.json").')
                    ->defaultNull()
                ->end()
            ->end();
    }
}
