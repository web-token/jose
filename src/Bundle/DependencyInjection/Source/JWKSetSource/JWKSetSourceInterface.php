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

interface JWKSetSourceInterface
{
    /**
     * Creates the JWKSet, registers it and returns its id.
     *
     * @param ContainerBuilder $container A ContainerBuilder instance
     * @param string           $type      The type of the service
     * @param string           $id        The id of the service
     * @param array            $config    An array of configuration
     */
    public function create(ContainerBuilder $container, $type, $id, array $config);

    /**
     * Returns the key set for the Key Set Source configuration.
     *
     * @return string
     */
    public function getKeySet();

    /**
     * Adds configuration nodes for this service.
     *
     * @param NodeDefinition $builder
     */
    public function addConfiguration(NodeDefinition $builder);
}
