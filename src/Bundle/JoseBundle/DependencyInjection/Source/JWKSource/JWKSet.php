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

namespace SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSource;

use SpomkyLabs\JoseBundle\DependencyInjection\Source\AbstractSource;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class JWKSet extends AbstractSource implements JWKSourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function createDefinition(ContainerBuilder $container, array $config)
    {
        $definition = new Definition('Jose\Component\Core\JWK');
        $definition->setFactory([
            new Reference('jose.factory.jwk'),
            'createFromKeySet',
        ]);
        $definition->setArguments([new Reference($config['key_set']), $config['index']]);

        return $definition;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return 'jwkset';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
                ->scalarNode('key_set')
                    ->info('The key set service.')
                    ->isRequired()->end()
                ->integerNode('index')
                    ->info('The index of the key in the key set.')
                    ->isRequired()
                ->end()
            ->end();
    }
}
