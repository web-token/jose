<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\Encryption\DependencyInjection\Compiler;

use Jose\Component\Encryption\Compression\CompressionMethodsManagerFactory;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class CompressionMethodCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition(CompressionMethodsManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(CompressionMethodsManagerFactory::class);

        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.compression_method');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            foreach ($tags as $attributes) {
                if (!array_key_exists('alias', $attributes)) {
                    throw new \InvalidArgumentException(sprintf("The compression method '%s' does not have any 'alias' attribute.", $id));
                }
                $definition->addMethodCall('add', [$attributes['alias'], new Reference($id)]);
            }
        }
    }
}
