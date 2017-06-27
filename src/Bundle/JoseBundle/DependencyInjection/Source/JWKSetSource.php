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
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;

final class JWKSetSource implements SourceInterface
{
    /**
     * @var null|\SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSetSource\JWKSetSourceInterface[]
     */
    private $jwkset_sources = null;

    /**
     * @var string
     */
    private $bundle_path = null;

    /**
     * JWKSetSource constructor.
     *
     * @param string $bundle_path
     */
    public function __construct($bundle_path)
    {
        $this->bundle_path = $bundle_path;
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'key_sets';
    }

    /**
     * {@inheritdoc}
     */
    public function createService($name, array $config, ContainerBuilder $container)
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
    public function prepend(ContainerBuilder $container, array $config)
    {
    }

    /**
     * @return array|\SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSetSource\JWKSetSourceInterface[]
     */
    private function getJWKSetSources()
    {
        if (null !== $this->jwkset_sources) {
            return $this->jwkset_sources;
        }

        // load bundled adapter factories
        $tempContainer = new ContainerBuilder();
        $loader = new XmlFileLoader($tempContainer, new FileLocator($this->bundle_path.'/Resources/config'));
        $loader->load('jwkset_sources.xml');

        $services = $tempContainer->findTaggedServiceIds('jose.jwk_set_source');
        $jwkset_sources = [];
        foreach (array_keys($services) as $id) {
            $factory = $tempContainer->get($id);
            $jwkset_sources[str_replace('-', '_', $factory->getKeySet())] = $factory;
        }

        return $this->jwkset_sources = $jwkset_sources;
    }
}
