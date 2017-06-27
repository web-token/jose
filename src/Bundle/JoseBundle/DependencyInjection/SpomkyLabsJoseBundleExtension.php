<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\DependencyInjection;

use Assert\Assertion;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

final class SpomkyLabsJoseBundleExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @var string
     */
    private $alias;

    /**
     * @var string
     */
    private $bundle_path;

    /**
     * @var \SpomkyLabs\JoseBundle\DependencyInjection\Source\SourceInterface[]
     */
    private $service_sources = [];

    /**
     * SpomkyLabsJoseBundleExtension constructor.
     *
     * @param string $alias
     * @param string $bundle_path
     */
    public function __construct($alias, $bundle_path)
    {
        $this->alias = $alias;
        $this->bundle_path = $bundle_path;
        $this->addDefaultSources();
    }

    /**
     * @param \SpomkyLabs\JoseBundle\DependencyInjection\Source\SourceInterface $source
     */
    public function addServiceSource(Source\SourceInterface $source)
    {
        $name = $source->getName();
        Assertion::false(in_array($name, $this->service_sources), sprintf('The source "%s" is already set.', $name));
        $this->service_sources[$name] = $source;
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $processor = new Processor();

        $config = $processor->processConfiguration(
            $this->getConfiguration($configs, $container),
            $configs
        );

        $loader = new XmlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $services = ['services', 'compression_methods', 'checkers', 'signature_algorithms', 'encryption_algorithms', 'checkers', 'jwkset_controller'];
        foreach ($services as $basename) {
            $loader->load(sprintf('%s.xml', $basename));
        }

        $this->initConfiguration($container, $config);
    }

    /**
     * @return \SpomkyLabs\JoseBundle\DependencyInjection\Configuration
     */
    public function getConfiguration(array $configs, ContainerBuilder $container)
    {
        return new Configuration($this->getAlias(), $this->service_sources);
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias()
    {
        return $this->alias;
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param array                                                   $config
     */
    private function initConfiguration(ContainerBuilder $container, array $config)
    {
        foreach ($this->service_sources as $service_source) {
            foreach ($config[$service_source->getName()] as $name => $data) {
                $service_source->createService($name, $data, $container);
            }
        }
    }

    private function addDefaultSources()
    {
        $this->addServiceSource(new Source\JWTCreatorSource());
        $this->addServiceSource(new Source\JWTLoaderSource());
        $this->addServiceSource(new Source\SignerSource());
        $this->addServiceSource(new Source\VerifierSource());
        $this->addServiceSource(new Source\EncrypterSource());
        $this->addServiceSource(new Source\DecrypterSource());
        $this->addServiceSource(new Source\CheckerSource());
        $this->addServiceSource(new Source\JWKSource($this->bundle_path));
        $this->addServiceSource(new Source\JWKSetSource($this->bundle_path));
        $this->addServiceSource(new Source\EasyJWTCreatorSource());
        $this->addServiceSource(new Source\EasyJWTLoaderSource());
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container)
    {
        $configs = $container->getExtensionConfig($this->getAlias());
        $config = $this->processConfiguration($this->getConfiguration($configs, $container), $configs);

        foreach ($this->service_sources as $service_source) {
            $result = $service_source->prepend($container, $config);
            if (null !== $result) {
                $container->prependExtensionConfig($this->getAlias(), $result);
            }
        }
    }
}
