<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\JWKSetSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\JWKSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceInterface;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

final class JoseFrameworkExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @var string
     */
    private $alias;

    /**
     * @var string
     */
    private $bundlePath;

    /**
     * @var SourceInterface[]
     */
    private $serviceSources = [];

    /**
     * JoseFrameworkExtension constructor.
     *
     * @param string $alias
     * @param string $bundlePath
     */
    public function __construct(string $alias, string $bundlePath)
    {
        $this->alias = $alias;
        $this->bundlePath = $bundlePath;
        $this->addDefaultSources();
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias(): string
    {
        return $this->alias;
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $processor = new Processor();
        $config = $processor->processConfiguration($this->getConfiguration($configs, $container), $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yml');

        // A translator must always be registered (as support is included by
        // default in the Form and Validator component). If disabled, an identity
        // translator will be used and everything will still work as expected.
        /*if ($this->isConfigEnabled($container, $config['translator']) || $this->isConfigEnabled($container, $config['form']) || $this->isConfigEnabled($container, $config['validation'])) {
            if (!class_exists('Symfony\Component\Translation\Translator') && $this->isConfigEnabled($container, $config['translator'])) {
                throw new LogicException('Translation support cannot be enabled as the Translation component is not installed.');
            }

            if (!class_exists('Symfony\Component\Translation\Translator') && $this->isConfigEnabled($container, $config['form'])) {
                throw new LogicException('Form support cannot be enabled as the Translation component is not installed.');
            }

            if (!class_exists('Symfony\Component\Translation\Translator') && $this->isConfigEnabled($container, $config['validation'])) {
                throw new LogicException('Validation support cannot be enabled as the Translation component is not installed.');
            }

            $loader->load('identity_translator.xml');
        }*/

        foreach ($this->serviceSources as $serviceSource) {
            foreach ($config[$serviceSource->name()] as $name => $data) {
                $serviceSource->createService($name, $data, $container);
            }
        }
    }

    /**
     * @param SourceInterface $source
     */
    public function addSource(SourceInterface $source)
    {
        $name = $source->name();
        if (in_array($name, $this->serviceSources)) {
            throw new \InvalidArgumentException(sprintf('The source "%s" is already set.', $name));
        }
        $this->serviceSources[$name] = $source;
    }

    /**
     * @param array            $configs
     * @param ContainerBuilder $container
     *
     * @return Configuration
     */
    public function getConfiguration(array $configs, ContainerBuilder $container): Configuration
    {
        return new Configuration($this->getAlias(), $this->serviceSources);
    }

    private function addDefaultSources()
    {
        $this->addSource(new JWKSource($this->bundlePath));
        $this->addSource(new JWKSetSource($this->bundlePath));
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container)
    {
        $configs = $container->getExtensionConfig($this->getAlias());
        $config = $this->processConfiguration($this->getConfiguration($configs, $container), $configs);

        foreach ($this->serviceSources as $serviceSource) {
            $result = $serviceSource->prepend($container, $config);
            if (null !== $result) {
                $container->prependExtensionConfig($this->getAlias(), $result);
            }
        }
    }
}
