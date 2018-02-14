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

interface JWKSetInterface extends \Countable, \Iterator, \JsonSerializable, \ArrayAccess
{
    /**
     * Get key from set at index.
     *
     * @param int $index
     *
     * @return \Jose\Object\JWKInterface
     */
    public function getKey($index);

    /**
     * Check if set has key at index.
     *
     * @param int $index
     *
     * @return bool
     */
    public function hasKey($index);

    /**
     * Returns all keys in the key set.
     *
     * @return \Jose\Object\JWKInterface[] An array of keys stored in the key set
     */
    public function getKeys();

    /**
     * Add key in the key set.
     *
     * @param \Jose\Object\JWKInterface $key A key to store in the key set
     */
    public function addKey(JWKInterface $key);

    /**
     * Prepend key to the set.
     *
     * @param \Jose\Object\JWKInterface $key A key to store in the key set
     */
    public function prependKey(JWKInterface $key);

    /**
     * Remove key from the key set.
     *
     * @param int $index Key to remove from the key set
     */
    public function removeKey($index);

    /**
     * @return int
     */
    public function countKeys();

    /**
     * @param string      $type         Must be 'sig' (signature) or 'enc' (encryption)
     * @param string|null $algorithm    Specifies the algorithm to be used
     * @param array       $restrictions More restrictions such as 'kid' or 'kty'
     *
     * @return \Jose\Object\JWKInterface|null
     */
    public function selectKey($type, $algorithm = null, array $restrictions = []);

    /**
     * Returns RSA/EC keys in the key set into PEM format
     * Note that if the key set contains other key types (none, oct, OKP...), they will not be part of the result.
     * If keys have a key ID, it is used as index.
     *
     * @return string[]
     */
    public function toPEM();
}
