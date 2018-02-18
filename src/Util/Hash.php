<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

class Hash
{
    /**
     * Hash Parameter.
     *
     * @var string
     */
    private $hash;

    /**
     * Hash Length.
     *
     * @var int
     */
    private $length;

    /**
     * @return \Jose\Util\Hash
     */
    public static function sha1()
    {
        return new self('sha1', 20);
    }

    /**
     * @return \Jose\Util\Hash
     */
    public static function sha256()
    {
        return new self('sha256', 32);
    }

    /**
     * @return \Jose\Util\Hash
     */
    public static function sha384()
    {
        return new self('sha384', 48);
    }

    /**
     * @return \Jose\Util\Hash
     */
    public static function sha512()
    {
        return new self('sha512', 64);
    }

    /**
     * @param string $hash
     * @param int    $length
     */
    private function __construct($hash, $length)
    {
        $this->hash = $hash;
        $this->length = $length;
    }

    /**
     * @return int
     */
    public function getLength()
    {
        return $this->length;
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
