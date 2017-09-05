<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Helper;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * This helper will help you to create services configuration.
 */
final class ConfigurationHelper
{
    const BUNDLE_ALIAS = 'jose';

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string[]         $signatureAlgorithms
     * @param bool             $is_public
     */
    public static function addJWSBuilder(ContainerBuilder $container, string $name, array $signatureAlgorithms, bool $is_public = true)
    {
        $config = self::getJWSBuilderConfiguration($name, $signatureAlgorithms, $is_public);
        self::updateJoseConfiguration($container, $config, 'jws_builders');
    }

    /**
     * @param string   $name
     * @param string[] $signatureAlgorithms
     * @param bool     $is_public
     *
     * @return array
     */
    private static function getJWSBuilderConfiguration(string $name, array $signatureAlgorithms, bool $is_public = true)
    {
        return [
            self::BUNDLE_ALIAS => [
                'jws_builders' => [
                    $name => [
                        'is_public'            => $is_public,
                        'signature_algorithms' => $signatureAlgorithms,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param ContainerBuilder $container
     * @param array            $config
     * @param string           $element
     */
    private static function updateJoseConfiguration(ContainerBuilder $container, array $config, string $element)
    {
        $jose_config = current($container->getExtensionConfig(self::BUNDLE_ALIAS));
        if (!isset($jose_config[$element])) {
            $jose_config[$element] = [];
        }
        $jose_config[$element] = array_merge($jose_config[$element], $config[self::BUNDLE_ALIAS][$element]);
        $container->prependExtensionConfig(self::BUNDLE_ALIAS, $jose_config);
    }
}
