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

final class JWKSource implements SourceInterface
{
    /**
     * @var null|\SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSource\JWKSourceInterface[]
     */
    private $jwk_sources = null;

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
        return 'keys';
    }

    /**
     * {@inheritdoc}
     */
    public function createService($name, array $config, ContainerBuilder $container)
    {
        foreach ($config as $key => $adapter) {
            if (array_key_exists($key, $this->getJWKSources())) {
                $this->getJWKSources()[$key]->create($container, 'key', $name, $adapter);

                return;
            }
        }
        throw new \LogicException(sprintf('The JWK definition "%s" is not configured.', $name));
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $sourceNodeBuilder = $node
            ->children()
                ->arrayNode('keys')
                    ->useAttributeAsKey('name')
                    ->prototype('array')
                        ->performNoDeepMerging()
                        ->children();
        foreach ($this->getJWKSources() as $name => $source) {
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
     * @return \SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSource\JWKSourceInterface[]
     */
    private function getJWKSources()
    {
        if (null !== $this->jwk_sources) {
            return $this->jwk_sources;
        }

        // load bundled adapter factories
        $tempContainer = new ContainerBuilder();
        $loader = new XmlFileLoader($tempContainer, new FileLocator($this->bundle_path.'/Resources/config'));
        $loader->load('jwk_sources.xml');

        $services = $tempContainer->findTaggedServiceIds('jose.jwk_source');
        $jwk_sources = [];
        foreach (array_keys($services) as $id) {
            $factory = $tempContainer->get($id);
            $jwk_sources[str_replace('-', '_', $factory->getKey())] = $factory;
        }

        $this->jwk_sources = $jwk_sources;

        return $jwk_sources;
    }
}
