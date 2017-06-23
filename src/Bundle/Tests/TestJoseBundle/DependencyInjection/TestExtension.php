<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\TestJoseBundle\DependencyInjection;

use SpomkyLabs\JoseBundle\Helper\ConfigurationHelper;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

final class TestExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @var string
     */
    private $alias;

    /**
     * @param string $alias
     */
    public function __construct($alias)
    {
        $this->alias = $alias;
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $loader = new XmlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.xml');
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias()
    {
        return $this->alias;
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container)
    {
        ConfigurationHelper::addChecker($container, 'test', ['crit'], ['iat', 'nbf', 'exp']);
        ConfigurationHelper::addRandomJWKSet($container, 'from_configuration_helper', '%kernel.cache_dir%/from_configuration_helper.keyset', 2, ['kty' => 'RSA', 'size' => 1024], true);
        ConfigurationHelper::addJWKSets($container, 'all_in_one_from_configuration_helper', ['jose.key_set.from_configuration_helper']);
        ConfigurationHelper::addPublicJWKSet($container, 'all_in_one_public_from_configuration_helper', 'jose.key_set.from_configuration_helper');

        ConfigurationHelper::addChecker($container, 'from_configuration_helper', ['crit'], ['exp', 'iat', 'nbf']);
        ConfigurationHelper::addSigner($container, 'from_configuration_helper', ['RS256']);
        ConfigurationHelper::addVerifier($container, 'from_configuration_helper', ['RS256']);
        ConfigurationHelper::addEncrypter($container, 'from_configuration_helper', ['RSA-OAEP-256'], ['A256GCM'], ['DEF']);
        ConfigurationHelper::addDecrypter($container, 'from_configuration_helper', ['RSA-OAEP-256'], ['A256GCM'], ['DEF']);
        ConfigurationHelper::addJWTLoader($container, 'from_configuration_helper', 'jose.verifier.from_configuration_helper', 'jose.checker.from_configuration_helper', 'jose.decrypter.from_configuration_helper');
        ConfigurationHelper::addJWTCreator($container, 'from_configuration_helper', 'jose.signer.from_configuration_helper', 'jose.encrypter.from_configuration_helper');
    }
}
