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

use Assert\Assertion;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class CheckerCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition('jose.checker_manager')) {
            return;
        }

        $definition = $container->getDefinition('jose.checker_manager');

        $this->addClaimCheckers($definition, $container);
        $this->addHeaderCheckers($definition, $container);
    }

    /**
     * @param \Symfony\Component\DependencyInjection\Definition       $definition
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     */
    private function addHeaderCheckers(Definition $definition, ContainerBuilder $container)
    {
        $taggedHeaderCheckerServices = $container->findTaggedServiceIds('jose.checker.header');
        foreach ($taggedHeaderCheckerServices as $id => $tags) {
            foreach ($tags as $attributes) {
                Assertion::keyExists($attributes, 'alias', sprintf("The header checker '%s' does not have any 'alias' attribute.", $id));
                $definition->addMethodCall('addHeaderChecker', [new Reference($id), $attributes['alias']]);
            }
        }
    }

    /**
     * @param \Symfony\Component\DependencyInjection\Definition       $definition
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     */
    private function addClaimCheckers(Definition $definition, ContainerBuilder $container)
    {
        $taggedClaimCheckerServices = $container->findTaggedServiceIds('jose.checker.claim');
        foreach ($taggedClaimCheckerServices as $id => $tags) {
            foreach ($tags as $attributes) {
                Assertion::keyExists($attributes, 'alias', sprintf("The claim checker '%s' does not have any 'alias' attribute.", $id));
                $definition->addMethodCall('addClaimChecker', [new Reference($id), $attributes['alias']]);
            }
        }
    }
}
