<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

interface JWKInterface extends \JsonSerializable
{
    /**
     * Get all values stored in the JWK object.
     *
     * @return array Values of the JWK object
     */
    public function getAll();

    /**
     * Get the value with a specific key.
     *
     * @param string $key The key
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed|null The value
     */
    public function get($key);

    /**
     * Returns true if the JWK has the value identified by.
     *
     * @param string $key The key
     *
     * @return bool
     */
    public function has($key);

    /**
     * Returns the thumbprint of the key.
     *
     * @see https://tools.ietf.org/html/rfc7638
     *
     * @param string $hash_algorithm
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    public function thumbprint($hash_algorithm);

    /**
     * @return \Jose\Object\JWKInterface
     */
    public function toPublic();
}
