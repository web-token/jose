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

abstract class DownloadedJWKSet extends AbstractJWKSetSource
{
    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
                ->scalarNode('url')->isRequired()->end()
                ->booleanNode('is_secured')->defaultTrue()->end()
                ->booleanNode('is_https')->defaultTrue()->end()
                ->scalarNode('cache')->defaultNull()->end()
                ->integerNode('cache_ttl')->defaultValue(86400)->end()
            ->end();
    }
}
