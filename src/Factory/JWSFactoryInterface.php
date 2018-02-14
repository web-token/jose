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

use Jose\Object\JWKInterface;

interface JWSFactoryInterface
{
    /**
     * @param mixed $payload
     * @param bool  $is_payload_detached
     *
     * @return \Jose\Object\JWSInterface
     */
    public static function createJWS($payload, $is_payload_detached = false);

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     *
     * @return string
     */
    public static function createJWSToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers);

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     *
     * @return string
     */
    public static function createJWSWithDetachedPayloadToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers);

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return string
     */
    public static function createJWSToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = []);

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return string
     */
    public static function createJWSWithDetachedPayloadToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = []);
}
