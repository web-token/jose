<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\JWKSetSource\JWKSetSourceInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

final class JWKSetSource implements SourceInterface
{
    /**
     * @var null|JWKSetSourceInterface[]
     */
    private $jwkset_sources = null;

    /**
     * @var string
     */
    private $bundlePath = null;

    /**
     * JWKSetSource constructor.
     *
     * @param string $bundlePath
     */
    public function __construct(string $bundlePath)
    {
        $this->bundlePath = $bundlePath;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'key_sets';
    }

    /**
     * {@inheritdoc}
     */
    public function createService(string $name, array $config, ContainerBuilder $container)
    {
        foreach ($config as $key => $adapter) {
            if (array_key_exists($key, $this->getJWKSetSources())) {
                $this->getJWKSetSources()[$key]->create($container, 'key_set', $name, $adapter);

                return;
            }
        }

        throw new \LogicException(sprintf('The JWKSet definition "%s" is not configured.', $name));
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $sourceNodeBuilder = $node
            ->children()
                ->arrayNode('key_sets')
                    ->useAttributeAsKey('name')
                    ->prototype('array')
                        ->performNoDeepMerging()
                        ->children();
        foreach ($this->getJWKSetSources() as $name => $source) {
            $sourceNode = $sourceNodeBuilder->arrayNode($name)->canBeUnset();
            $source->addConfiguration($sourceNode);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config): ?array
    {
        return null;
    }

    /**
     * @return JWKSetSourceInterface[]
     */
    private function getJWKSetSources(): array
    {
        if (null !== $this->jwkset_sources) {
            return $this->jwkset_sources;
        }

        // load bundled adapter factories
        $tempContainer = new ContainerBuilder();
        $loader = new YamlFileLoader($tempContainer, new FileLocator($this->bundlePath.'/Resources/config'));
        $loader->load('jwkset_sources.yml');

        $services = $tempContainer->findTaggedServiceIds('jose.jwkset_source');
        $jwkset_sources = [];
        foreach (array_keys($services) as $id) {
            $factory = $tempContainer->get($id);
            $jwkset_sources[str_replace('-', '_', $factory->getKeySet())] = $factory;
        }

        return $this->jwkset_sources = $jwkset_sources;
    }
}
