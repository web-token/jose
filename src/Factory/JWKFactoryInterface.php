<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Jose\Object\JWKSetInterface;
use Psr\Cache\CacheItemPoolInterface;

interface JWKFactoryInterface
{
    /**
     * @param \Jose\Object\JWKSetInterface $jwkset
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createPublicKeySet(JWKSetInterface $jwkset);

    /**
     * @param \Jose\Object\JWKSetInterface[] $jwksets
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createKeySets(array $jwksets = []);

    /**
     * @param string $filename
     * @param array  $parameters
     * @param int    $nb_keys
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createStorableKeySet($filename, array $parameters, $nb_keys);

    /**
     * @param string   $filename
     * @param array    $parameters
     * @param int      $nb_keys
     * @param int|null $interval
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createRotatableKeySet($filename, array $parameters, $nb_keys, $interval = null);

    /**
     * @param string $filename
     * @param array  $parameters
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createStorableKey($filename, array $parameters);

    /**
     * @param array $config
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createKey(array $config);

    /**
     * @param array $values Values to configure the key. Must contain at least the index 'size' with the key size in bits
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createRSAKey(array $values);

    /**
     * @param array $values Values to configure the key. Must contain at least the index 'crv' with the curve
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createECKey(array $values);

    /**
     * @param array $values Values to configure the key. Must contain at least the index 'size' with the key size in bits
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createOctKey(array $values);

    /**
     * @param array $values Values to configure the key. Must contain at least the index 'crv' with the curve
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createOKPKey(array $values);

    /**
     * @param array $values values to configure the key
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createNoneKey(array $values);

    /**
     * @param array $values
     *
     * @return \Jose\Object\JWKInterface|\Jose\Object\JWKSetInterface
     */
    public static function createFromValues(array $values);

    /**
     * @param string $file
     * @param array  $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromCertificateFile($file, array $additional_values = []);

    /**
     * @param string $certificate
     * @param array  $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromCertificate($certificate, array $additional_values = []);

    /**
     * @param resource $res
     * @param array    $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromX509Resource($res, array $additional_values = []);

    /**
     * @param string      $file
     * @param null|string $password
     * @param array       $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromKeyFile($file, $password = null, array $additional_values = []);

    /**
     * @param string      $key
     * @param null|string $password
     * @param array       $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromKey($key, $password = null, array $additional_values = []);

    /**
     * @param string                                 $jku
     * @param bool                                   $allow_unsecured_connection
     * @param \Psr\Cache\CacheItemPoolInterface|null $cache
     * @param int|null                               $ttl
     * @param bool                                   $allow_http_connection
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createFromJKU($jku, $allow_unsecured_connection = false, CacheItemPoolInterface $cache = null, $ttl = 86400, $allow_http_connection = false);

    /**
     * @param string                                 $x5u
     * @param bool                                   $allow_unsecured_connection
     * @param \Psr\Cache\CacheItemPoolInterface|null $cache
     * @param int|null                               $ttl
     * @param bool                                   $allow_http_connection
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createFromX5U($x5u, $allow_unsecured_connection = false, CacheItemPoolInterface $cache = null, $ttl = 86400, $allow_http_connection = false);

    /**
     * @param array $x5c
     * @param array $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromX5C(array $x5c, array $additional_values = []);

    /**
     * @param \Jose\Object\JWKSetInterface $jwk_set
     * @param int                          $key_index
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromKeySet(JWKSetInterface $jwk_set, $key_index);
}
