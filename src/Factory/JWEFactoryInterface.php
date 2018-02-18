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

interface JWEFactoryInterface
{
    /**
     * @param mixed       $payload
     * @param array       $shared_protected_headers
     * @param array       $shared_headers
     * @param null|string $aad
     *
     * @return \Jose\Object\JWEInterface
     */
    public static function createJWE($payload, array $shared_protected_headers = [], array $shared_headers = [], $aad = null);

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $recipient_key
     * @param array                     $shared_protected_headers
     *
     * @return string
     */
    public static function createJWEToCompactJSON($payload, JWKInterface $recipient_key, array $shared_protected_headers);

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $recipient_key
     * @param array                     $shared_protected_headers
     * @param array                     $shared_headers
     * @param array                     $recipient_headers
     * @param string|null               $aad
     *
     * @return string
     */
    public static function createJWEToFlattenedJSON($payload, JWKInterface $recipient_key, array $shared_protected_headers = [], $shared_headers = [], $recipient_headers = [], $aad = null);
}
