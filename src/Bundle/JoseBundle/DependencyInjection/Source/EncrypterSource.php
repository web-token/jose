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

final class EncrypterSource implements SourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'encrypters';
    }

    /**
     * {@inheritdoc}
     */
    public function createService($name, array $config, ContainerBuilder $container)
    {
        $service_id = sprintf('jose.encrypter.%s', $name);
        $definition = new Definition('Jose\Encrypter');
        $definition->setFactory([
            new Reference('jose.factory.service'),
            'createEncrypter',
        ]);
        $definition->setArguments([
            $config['key_encryption_algorithms'],
            $config['content_encryption_algorithms'],
            $config['compression_methods'],
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
                            ->arrayNode('key_encryption_algorithms')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('content_encryption_algorithms')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('compression_methods')
                                ->useAttributeAsKey('name')
                                ->defaultValue(['DEF'])
                                ->prototype('scalar')->end()
                            ->end()
                            ->booleanNode('create_decrypter')
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
            if (true === $section['create_decrypter']) {
                $values = $section;
                unset($values['create_decrypter']);
                $config['decrypters'] = array_merge(
                    array_key_exists('decrypters', $config) ? $config['decrypters'] : [],
                    [$id => $values]
                );
            }
        }

        return $config;
    }
}
