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

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class SignerSource implements SourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'signers';
    }

    /**
     * {@inheritdoc}
     */
    public function createService($name, array $config, ContainerBuilder $container)
    {
        $service_id = sprintf('jose.signer.%s', $name);
        $definition = new Definition('Jose\Signer');
        $definition->setFactory([
            new Reference('jose.factory.service'),
            'createSigner',
        ]);
        $definition->setArguments([
            $config['algorithms'],
        ]);
        $definition->setPublic($config['is_public']);

        $container->setDefinition($service_id, $definition);
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode($this->getName())
                    ->useAttributeAsKey('name')
                    ->prototype('array')
                        ->children()
                            ->booleanNode('is_public')
                                ->info('If true, the service will be public, else private.')
                                ->defaultTrue()
                            ->end()
                            ->arrayNode('algorithms')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->prototype('scalar')->end()
                            ->end()
                            ->booleanNode('create_verifier')
                                ->defaultFalse()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config)
    {
        if (false === array_key_exists($this->getName(), $config)) {
            return;
        }

        foreach ($config[$this->getName()] as $id => $section) {
            if (true === $section['create_verifier']) {
                $values = $section;
                unset($values['create_verifier']);
                $config['verifiers'] = array_merge(
                    array_key_exists('verifiers', $config) ? $config['verifiers'] : [],
                    [$id => $values]
                );
            }
        }

        return $config;
    }
}
