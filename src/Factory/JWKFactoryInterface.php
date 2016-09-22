<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Psr\Cache\CacheItemPoolInterface;

interface JWKFactoryInterface
{
    /**
     * RotatableJWK constructor.
     *
     * @param string $filename
     * @param array  $parameters
     * @param int    $nb_keys
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createStorableKeySet($filename, array $parameters, $nb_keys);

    /**
     * RotatableJWK constructor.
     *
     * @param string $filename
     * @param array  $parameters
     * @param int    $nb_keys
     * @param int    $ttl
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createRotatableKeySet($filename, array $parameters, $nb_keys, $ttl);

    /**
     * RotatableJWK constructor.
     *
     * @param string $filename
     * @param array  $parameters
     * @param int    $ttl
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createRotatableKey($filename, array $parameters, $ttl);

    /**
     * RotatableJWK constructor.
     *
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
     * @param array $values Values to configure the key.
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
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createFromJKU($jku, $allow_unsecured_connection = false, CacheItemPoolInterface $cache = null);

    /**
     * @param string                                 $x5u
     * @param bool                                   $allow_unsecured_connection
     * @param \Psr\Cache\CacheItemPoolInterface|null $cache
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createFromX5U($x5u, $allow_unsecured_connection = false, CacheItemPoolInterface $cache = null);

    /**
     * @param array $x5c
     * @param array $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromX5C(array $x5c, array $additional_values = []);
}
