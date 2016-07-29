<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

use Assert\Assertion;

class Hash
{
    /**
     * Hash Parameter.
     *
     * @var int
     */
    private $hash;

    /**
     * Default Constructor.
     *
     * @param string $hash
     */
    public function __construct($hash)
    {
        Assertion::string($hash);
        Assertion::inArray($hash, hash_algos());
        $this->hash = $hash;
    }

    /**
     * Gets the hash function.
     *
     * As set by the constructor or by the setHash() method.
     *
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * Compute the HMAC.
     *
     * @param string $text
     *
     * @return string
     */
    public function hash($text)
    {
        return hash($this->hash, $text, true);
    }
}
