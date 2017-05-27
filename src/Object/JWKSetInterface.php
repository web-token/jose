<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

interface JWKSetInterface extends \Countable, \Iterator, \JsonSerializable, \ArrayAccess
{
    /**
     * @param $index
     *
     * @return JWKInterface
     */
    public function getKey(int $index): JWKInterface;

    /**
     * @param $index
     *
     * @return bool
     */
    public function hasKey(int $index): bool;

    /**
     * Returns all keys in the key set.
     *
     * @return JWKInterface[] An array of keys stored in the key set
     */
    public function getKeys(): array;

    /**
     * Add key in the key set.
     *
     * @param JWKInterface $key A key to store in the key set
     */
    public function addKey(JWKInterface $key);

    /**
     * Remove key from the key set.
     *
     * @param int $index Key to remove from the key set
     */
    public function removeKey(int $index);

    /**
     * @return int
     */
    public function countKeys(): int;

    /**
     * @param string      $type         Must be 'sig' (signature) or 'enc' (encryption)
     * @param string|null $algorithm    Specifies the algorithm to be used
     * @param array       $restrictions More restrictions such as 'kid' or 'kty'
     *
     * @return JWKInterface|null
     */
    public function selectKey(string $type, ?string $algorithm = null, array $restrictions = []): ?JWKInterface;

    /**
     * Returns RSA/EC keys in the key set into PEM format
     * Note that if the key set contains other key types (none, oct, OKP...), they will not be part of the result.
     * If keys have a key ID, it is used as index.
     *
     * @return string[]
     */
    public function toPEM(): array;
}
