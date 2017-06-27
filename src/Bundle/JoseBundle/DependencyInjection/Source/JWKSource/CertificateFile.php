<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSource;

use SpomkyLabs\JoseBundle\DependencyInjection\Source\AbstractSource;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class CertificateFile extends AbstractSource implements JWKSourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function createDefinition(ContainerBuilder $container, array $config)
    {
        $definition = new Definition('Jose\Component\Core\JWK');
        $definition->setFactory([
            new Reference('jose.factory.jwk'),
            'createFromCertificateFile',
        ]);
        $definition->setArguments([
            $config['path'],
            $config['additional_values'],
        ]);

        return $definition;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return 'certificate';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
                ->scalarNode('path')->isRequired()->end()
                ->arrayNode('additional_values')
                    ->defaultValue([])
                    ->useAttributeAsKey('key')
                    ->prototype('variable')->end()
                ->end()
            ->end();
    }
}
