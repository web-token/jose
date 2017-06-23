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

final class EasyJWTLoaderSource implements SourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'easy_jwt_loader';
    }

    /**
     * {@inheritdoc}
     */
    public function createService($name, array $config, ContainerBuilder $container)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode('easy_jwt_loader')
                    ->useAttributeAsKey('name')
                    ->prototype('array')
                        ->children()
                            ->booleanNode('is_public')
                                ->info('If true, the service will be public, else private.')
                                ->defaultTrue()
                            ->end()
                            ->arrayNode('signature_algorithms')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->cannotBeEmpty()
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('key_encryption_algorithms')
                                ->useAttributeAsKey('name')
                                ->defaultValue([])
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('content_encryption_algorithms')
                                ->useAttributeAsKey('name')
                                ->defaultValue([])
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('compression_methods')
                                ->useAttributeAsKey('name')
                                ->defaultValue(['DEF'])
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('claim_checkers')
                                ->useAttributeAsKey('name')
                                ->defaultValue([])
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('header_checkers')
                                ->useAttributeAsKey('name')
                                ->defaultValue([])
                                ->prototype('scalar')->end()
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
            $config = $this->createServiceConfiguration($config, $id, $section);
        }

        return $config;
    }

    /**
     * @param array  $config
     * @param string $id
     * @param array  $section
     *
     * @return array
     */
    private function createServiceConfiguration(array $config, $id, array $section)
    {
        $config = $this->createVerifierServiceConfiguration($config, $id, $section);
        $config = $this->createDecrypterServiceConfiguration($config, $id, $section);
        $config = $this->createJWTLoaderServiceConfiguration($config, $id, $section);
        $config = $this->createCheckerServiceConfiguration($config, $id, $section);

        return $config;
    }

    /**
     * @param array  $config
     * @param string $id
     * @param array  $section
     *
     * @return array
     */
    private function createVerifierServiceConfiguration(array $config, $id, array $section)
    {
        $config['verifiers'] = array_merge(
            array_key_exists('verifiers', $config) ? $config['verifiers'] : [],
            [$id => [
                'is_public'  => $section['is_public'],
                'algorithms' => $section['signature_algorithms'],
            ]]
        );

        return $config;
    }

    /**
     * @param array  $config
     * @param string $id
     * @param array  $section
     *
     * @return array
     */
    private function createDecrypterServiceConfiguration(array $config, $id, array $section)
    {
        if (false === $this->isEncryptionSupportEnabled($section)) {
            return $config;
        }
        $config['decrypters'] = array_merge(
            array_key_exists('decrypters', $config) ? $config['decrypters'] : [],
            [$id => [
                'is_public'                     => $section['is_public'],
                'key_encryption_algorithms'     => $section['key_encryption_algorithms'],
                'content_encryption_algorithms' => $section['content_encryption_algorithms'],
                'compression_methods'           => $section['compression_methods'],
            ]]
        );

        return $config;
    }

    /**
     * @param array  $config
     * @param string $id
     * @param array  $section
     *
     * @return array
     */
    private function createCheckerServiceConfiguration(array $config, $id, array $section)
    {
        $config['checkers'] = array_merge(
            array_key_exists('checkers', $config) ? $config['checkers'] : [],
            [$id => [
                'is_public' => $section['is_public'],
                'claims'    => $section['claim_checkers'],
                'headers'   => $section['header_checkers'],
            ]]
        );

        return $config;
    }

    /**
     * @param array  $config
     * @param string $id
     * @param array  $section
     *
     * @return array
     */
    private function createJWTLoaderServiceConfiguration(array $config, $id, array $section)
    {
        $service = [
            'is_public' => $section['is_public'],
            'verifier'  => sprintf('jose.verifier.%s', $id),
            'checker'   => sprintf('jose.checker.%s', $id),
        ];
        if (true === $this->isEncryptionSupportEnabled($section)) {
            $service['decrypter'] = sprintf('jose.decrypter.%s', $id);
        }
        $config['jwt_loaders'] = array_merge(
            array_key_exists('jwt_loaders', $config) ? $config['jwt_loaders'] : [],
            [$id => $service]
        );

        return $config;
    }

    /**
     * @param array $section
     *
     * @return bool
     */
    private function isEncryptionSupportEnabled(array $section)
    {
        if (true === empty($section['key_encryption_algorithms']) && true === empty($section['content_encryption_algorithms'])) {
            return false;
        }

        if (true === empty($section['key_encryption_algorithms']) || true === empty($section['content_encryption_algorithms'])) {
            throw new \LogicException('Both key encryption algorithms and content encryption algorithms must be set to enable the encryption support.');
        }

        return true;
    }
}
