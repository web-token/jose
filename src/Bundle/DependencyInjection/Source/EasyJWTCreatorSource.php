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

final class EasyJWTCreatorSource implements SourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'easy_jwt_creator';
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
                ->arrayNode('easy_jwt_creator')
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
        $config = $this->createSignerServiceConfiguration($config, $id, $section);
        $config = $this->createEncrypterServiceConfiguration($config, $id, $section);
        $config = $this->createJWTCreatorServiceConfiguration($config, $id, $section);

        return $config;
    }

    /**
     * @param array  $config
     * @param string $id
     * @param array  $section
     *
     * @return array
     */
    private function createSignerServiceConfiguration(array $config, $id, array $section)
    {
        $config['signers'] = array_merge(
            array_key_exists('signers', $config) ? $config['signers'] : [],
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
    private function createEncrypterServiceConfiguration(array $config, $id, array $section)
    {
        if (false === $this->isEncryptionSupportEnabled($section)) {
            return $config;
        }
        $config['encrypters'] = array_merge(
            array_key_exists('encrypters', $config) ? $config['encrypters'] : [],
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
    private function createJWTCreatorServiceConfiguration(array $config, $id, array $section)
    {
        $service = [
            'is_public' => $section['is_public'],
            'signer'    => sprintf('jose.signer.%s', $id),
        ];
        if (true === $this->isEncryptionSupportEnabled($section)) {
            $service['encrypter'] = sprintf('jose.encrypter.%s', $id);
        }
        $config['jwt_creators'] = array_merge(
            array_key_exists('jwt_creators', $config) ? $config['jwt_creators'] : [],
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
