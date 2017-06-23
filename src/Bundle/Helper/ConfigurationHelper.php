<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Helper;

use Assert\Assertion;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * This helper will help you to create services configuration.
 */
final class ConfigurationHelper
{
    const BUNDLE_ALIAS = 'jose';

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string[]                                                $header_checkers
     * @param string[]                                                $claim_checkers
     * @param bool                                                    $is_public
     */
    public static function addChecker(ContainerBuilder $container, $name, array $header_checkers, array $claim_checkers, $is_public = true)
    {
        $config = self::getCheckerConfiguration($name, $header_checkers, $claim_checkers, $is_public);
        self::updateJoseConfiguration($container, $config, 'checkers');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string[]                                                $signature_algorithms
     * @param bool                                                    $create_verifier
     * @param bool                                                    $is_public
     */
    public static function addSigner(ContainerBuilder $container, $name, array $signature_algorithms, $create_verifier = false, $is_public = true)
    {
        $config = self::getSignerConfiguration($name, $signature_algorithms, $create_verifier, $is_public);
        self::updateJoseConfiguration($container, $config, 'signers');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string[]                                                $signature_algorithms
     * @param bool                                                    $is_public
     */
    public static function addVerifier(ContainerBuilder $container, $name, array $signature_algorithms, $is_public = true)
    {
        $config = self::getVerifierConfiguration($name, $signature_algorithms, $is_public);
        self::updateJoseConfiguration($container, $config, 'verifiers');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string[]                                                $key_encryption_algorithms
     * @param string[]                                                $content_encryption_algorithms
     * @param string[]                                                $compression_methods
     * @param bool                                                    $create_decrypter
     * @param bool                                                    $is_public
     */
    public static function addEncrypter(ContainerBuilder $container, $name, array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF'], $create_decrypter = false, $is_public = true)
    {
        $config = self::getEncrypterConfiguration($name, $key_encryption_algorithms, $content_encryption_algorithms, $compression_methods, $create_decrypter, $is_public);
        self::updateJoseConfiguration($container, $config, 'encrypters');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string[]                                                $key_encryption_algorithms
     * @param string[]                                                $content_encryption_algorithms
     * @param string[]                                                $compression_methods
     * @param bool                                                    $is_public
     */
    public static function addDecrypter(ContainerBuilder $container, $name, array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF'], $is_public = true)
    {
        $config = self::getDecrypterConfiguration($name, $key_encryption_algorithms, $content_encryption_algorithms, $compression_methods, $is_public);
        self::updateJoseConfiguration($container, $config, 'decrypters');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string                                                  $signer
     * @param string|null                                             $encrypter
     * @param bool                                                    $is_public
     */
    public static function addJWTCreator(ContainerBuilder $container, $name, $signer, $encrypter = null, $is_public = true)
    {
        $config = self::getJWTCreatorConfiguration($name, $signer, $encrypter, $is_public);
        self::updateJoseConfiguration($container, $config, 'jwt_creators');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string                                                  $verifier
     * @param string                                                  $checker
     * @param string|null                                             $decrypter
     * @param bool                                                    $is_public
     */
    public static function addJWTLoader(ContainerBuilder $container, $name, $verifier, $checker, $decrypter = null, $is_public = true)
    {
        $config = self::getJWTLoaderConfiguration($name, $verifier, $checker, $decrypter, $is_public);
        self::updateJoseConfiguration($container, $config, 'jwt_loaders');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string                                                  $storage_path
     * @param int                                                     $nb_keys
     * @param array                                                   $key_configuration
     * @param bool                                                    $is_rotatable
     * @param bool                                                    $is_public
     */
    public static function addRandomJWKSet(ContainerBuilder $container, $name, $storage_path, $nb_keys, array $key_configuration, $is_rotatable = false, $is_public = true)
    {
        $config = self::getRandomJWKSetConfiguration($name, $storage_path, $nb_keys, $key_configuration, $is_rotatable, $is_public);
        self::updateJoseConfiguration($container, $config, 'key_sets');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string                                                  $jwkset
     * @param bool                                                    $is_public
     */
    public static function addPublicJWKSet(ContainerBuilder $container, $name, $jwkset, $is_public = true)
    {
        $config = self::getPublicJWKSetConfiguration($name, $jwkset, $is_public);
        self::updateJoseConfiguration($container, $config, 'key_sets');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param string                                                  $name
     * @param string[]                                                $jwksets
     * @param bool                                                    $is_public
     */
    public static function addJWKSets(ContainerBuilder $container, $name, array $jwksets, $is_public = true)
    {
        $config = self::getJWKSetsConfiguration($name, $jwksets, $is_public);
        self::updateJoseConfiguration($container, $config, 'key_sets');
    }

    /**
     * @param string   $name
     * @param string[] $header_checkers
     * @param string[] $claim_checkers
     * @param bool     $is_public
     *
     * @return array
     */
    private static function getCheckerConfiguration($name, array $header_checkers, array $claim_checkers, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::allString($header_checkers);
        Assertion::allString($claim_checkers);

        return [
            self::BUNDLE_ALIAS => [
                'checkers' => [
                    $name => [
                        'is_public' => $is_public,
                        'claims'    => $claim_checkers,
                        'headers'   => $header_checkers,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string   $name
     * @param string[] $signature_algorithms
     * @param bool     $create_verifier
     * @param bool     $is_public
     *
     * @return array
     */
    private static function getSignerConfiguration($name, array $signature_algorithms, $create_verifier = false, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::allString($signature_algorithms);
        Assertion::notEmpty($signature_algorithms);
        Assertion::boolean($create_verifier);

        return [
            self::BUNDLE_ALIAS => [
                'signers' => [
                    $name => [
                        'is_public'       => $is_public,
                        'algorithms'      => $signature_algorithms,
                        'create_verifier' => $create_verifier,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string   $name
     * @param string[] $signature_algorithms
     * @param bool     $is_public
     *
     * @return array
     */
    private static function getVerifierConfiguration($name, array $signature_algorithms, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::allString($signature_algorithms);
        Assertion::notEmpty($signature_algorithms);

        return [
            self::BUNDLE_ALIAS => [
                'verifiers' => [
                    $name => [
                        'is_public'  => $is_public,
                        'algorithms' => $signature_algorithms,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string   $name
     * @param string[] $key_encryption_algorithms
     * @param string[] $content_encryption_algorithms
     * @param string[] $compression_methods
     * @param bool     $create_decrypter
     * @param bool     $is_public
     *
     * @return array
     */
    private static function getEncrypterConfiguration($name, array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF'], $create_decrypter = false, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::allString($key_encryption_algorithms);
        Assertion::notEmpty($key_encryption_algorithms);
        Assertion::allString($content_encryption_algorithms);
        Assertion::notEmpty($content_encryption_algorithms);
        Assertion::boolean($create_decrypter);

        return [
            self::BUNDLE_ALIAS => [
                'encrypters' => [
                    $name => [
                        'is_public'                     => $is_public,
                        'key_encryption_algorithms'     => $key_encryption_algorithms,
                        'content_encryption_algorithms' => $content_encryption_algorithms,
                        'compression_methods'           => $compression_methods,
                        'create_decrypter'              => $create_decrypter,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string   $name
     * @param string[] $key_encryption_algorithms
     * @param string[] $content_encryption_algorithms
     * @param string[] $compression_methods
     * @param bool     $is_public
     *
     * @return array
     */
    private static function getDecrypterConfiguration($name, array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF'], $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::allString($key_encryption_algorithms);
        Assertion::notEmpty($key_encryption_algorithms);
        Assertion::allString($content_encryption_algorithms);
        Assertion::notEmpty($content_encryption_algorithms);

        return [
            self::BUNDLE_ALIAS => [
                'decrypters' => [
                    $name => [
                        'is_public'                     => $is_public,
                        'key_encryption_algorithms'     => $key_encryption_algorithms,
                        'content_encryption_algorithms' => $content_encryption_algorithms,
                        'compression_methods'           => $compression_methods,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string      $name
     * @param string      $signer
     * @param string|null $encrypter
     * @param bool        $is_public
     *
     * @return array
     */
    private static function getJWTCreatorConfiguration($name, $signer, $encrypter = null, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::string($signer);
        Assertion::notEmpty($signer);
        Assertion::nullOrString($encrypter);

        return [
            self::BUNDLE_ALIAS => [
                'jwt_creators' => [
                    $name => [
                        'is_public' => $is_public,
                        'signer'    => $signer,
                        'encrypter' => $encrypter,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string      $name
     * @param string      $verifier
     * @param string      $checker
     * @param string|null $decrypter
     * @param bool        $is_public
     *
     * @return array
     */
    private static function getJWTLoaderConfiguration($name, $verifier, $checker, $decrypter = null, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::string($verifier);
        Assertion::notEmpty($verifier);
        Assertion::string($checker);
        Assertion::notEmpty($checker);
        Assertion::nullOrString($decrypter);

        return [
            self::BUNDLE_ALIAS => [
                'jwt_loaders' => [
                    $name => [
                        'is_public' => $is_public,
                        'verifier'  => $verifier,
                        'checker'   => $checker,
                        'decrypter' => $decrypter,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string $name
     * @param string $storage_path
     * @param int    $nb_keys
     * @param array  $key_configuration
     * @param bool   $is_rotatable
     * @param bool   $is_public
     *
     * @return array
     */
    private static function getRandomJWKSetConfiguration($name, $storage_path, $nb_keys, array $key_configuration, $is_rotatable = false, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::string($storage_path);
        Assertion::notEmpty($storage_path);
        Assertion::integer($nb_keys);
        Assertion::greaterThan($nb_keys, 0);
        Assertion::boolean($is_rotatable);

        return [
            self::BUNDLE_ALIAS => [
                'key_sets' => [
                    $name => [
                        'auto' => [
                            'is_rotatable'      => $is_rotatable,
                            'is_public'         => $is_public,
                            'nb_keys'           => $nb_keys,
                            'key_configuration' => $key_configuration,
                            'storage_path'      => $storage_path,
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string $name
     * @param string $jwkset
     * @param bool   $is_public
     *
     * @return array
     */
    private static function getPublicJWKSetConfiguration($name, $jwkset, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::string($jwkset);
        Assertion::notEmpty($jwkset);

        return [
            self::BUNDLE_ALIAS => [
                'key_sets' => [
                    $name => [
                        'public_jwkset' => [
                            'is_public' => $is_public,
                            'id'        => $jwkset,
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string   $name
     * @param string[] $jwksets
     * @param bool     $is_public
     *
     * @return array
     */
    private static function getJWKSetsConfiguration($name, array $jwksets, $is_public = true)
    {
        self::checkParameters($name, $is_public);
        Assertion::isArray($jwksets);
        Assertion::allString($jwksets);
        Assertion::allNotEmpty($jwksets);

        return [
            self::BUNDLE_ALIAS => [
                'key_sets' => [
                    $name => [
                        'jwksets' => [
                            'is_public' => $is_public,
                            'id'        => $jwksets,
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * @param string $name
     * @param bool   $is_public
     */
    private static function checkParameters($name, $is_public)
    {
        Assertion::string($name);
        Assertion::notEmpty($name);
        Assertion::boolean($is_public);
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param array                                                   $config
     * @param string                                                  $element
     */
    private static function updateJoseConfiguration(ContainerBuilder $container, array $config, $element)
    {
        self::checkJoseBundleEnabled($container);
        $jose_config = current($container->getExtensionConfig(self::BUNDLE_ALIAS));
        if (!isset($jose_config[$element])) {
            $jose_config[$element] = [];
        }
        $jose_config[$element] = array_merge($jose_config[$element], $config[self::BUNDLE_ALIAS][$element]);
        $container->prependExtensionConfig(self::BUNDLE_ALIAS, $jose_config);
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     *
     * @throws \InvalidArgumentException
     */
    private static function checkJoseBundleEnabled(ContainerBuilder $container)
    {
        $bundles = $container->getParameter('kernel.bundles');
        Assertion::keyExists($bundles, 'SpomkyLabsJoseBundle', 'The "Spomky-Labs/JoseBundle" must be enabled.');
    }
}
