<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class AlgorithmCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition('jose.algorithm_manager')) {
            return;
        }

        $definition = $container->getDefinition('jose.algorithm_manager');

        $taggedServices = $container->findTaggedServiceIds('jose.algorithm');
        foreach ($taggedServices as $id => $tags) {
            $definition->addMethodCall('addAlgorithm', [new Reference($id)]);
        }
    }
}
