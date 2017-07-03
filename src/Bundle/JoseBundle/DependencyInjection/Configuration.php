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

namespace SpomkyLabs\JoseBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    /**
     * @var \SpomkyLabs\JoseBundle\DependencyInjection\Source\SourceInterface[]
     */
    private $service_sources;

    /**
     * @var string
     */
    private $alias;

    /**
     * Configuration constructor.
     *
     * @param string                                                              $alias
     * @param \SpomkyLabs\JoseBundle\DependencyInjection\Source\SourceInterface[] $service_sources
     */
    public function __construct($alias, array $service_sources)
    {
        $this->alias = $alias;
        $this->service_sources = $service_sources;
    }

    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root($this->alias);

        foreach ($this->service_sources as $service_source) {
            $service_source->getNodeDefinition($rootNode);
        }

        return $treeBuilder;
    }
}
