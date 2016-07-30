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

final class BigInteger
{
    /**
     * Holds the BigInteger's value.
     *
     * @var resource
     */
    private $value;

    /**
     * Converts base-10 and binary strings (base-256) to BigIntegers.
     *
     * @param \GMP|string $value
     * @param int         $base
     */
    private function __construct($value, $base)
    {
        if ($value instanceof \GMP) {
            $this->value = $value;

            return;
        }

        $this->value = gmp_init($value, $base);
    }

    /**
     * @param \GMP $value
     *
     * @return \Jose\Util\BigInteger
     */
    public static function createFromGMPResource($value)
    {
        Assertion::isInstanceOf($value, \GMP::class);

        return new self($value, 0);
    }

    /**
     * @param string $value
     *
     * @return \Jose\Util\BigInteger
     */
    public static function createFromBinaryString($value)
    {
        Assertion::string($value);
        $value = '0x'.bin2hex($value);

        return new self($value, 16);
    }

    /**
     * @param string $value
     *
     * @return \Jose\Util\BigInteger
     */
    public static function createFromDecimalString($value)
    {
        Assertion::string($value);

        return new self($value, 10);
    }

    /**
     * Converts a BigInteger to a byte string (eg. base-256).
     *
     * @return string
     */
    public function toBytes()
    {
        if (gmp_cmp($this->value, gmp_init(0)) === 0) {
            return '';
        }

        $temp = gmp_strval(gmp_abs($this->value), 16);
        $temp = (strlen($temp) & 1) ? '0'.$temp : $temp;
        $temp = hex2bin($temp);

        return ltrim($temp, chr(0));
    }

    /**
     * Divides two BigIntegers.
     *
     * @param \Jose\Util\BigInteger $y
     *
     * @return \Jose\Util\BigInteger[]
     */
    public function divide(BigInteger $y)
    {
        list($quotient_value, $remainder_value) = gmp_div_qr($this->value, $y->value);

        if (gmp_sign($remainder_value) < 0) {
            $remainder_value = gmp_add($remainder_value, gmp_abs($y->value));
        }

        return [self::createFromGMPResource($quotient_value), self::createFromGMPResource($remainder_value)];
    }

    /**
     * Performs modular exponentiation.
     *
     * @param \Jose\Util\BigInteger $e
     * @param \Jose\Util\BigInteger $n
     *
     * @return \Jose\Util\BigInteger|bool
     */
    public function modPow(BigInteger $e, BigInteger $n)
    {
        $value = gmp_powm($this->value, $e->value, $n->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Absolute value.
     *
     * @return \Jose\Util\BigInteger
     */
    public function abs()
    {
        $value = gmp_abs($this->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Compares two numbers.
     *
     * @param \Jose\Util\BigInteger $y
     *
     * @return int < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal.
     */
    public function compare(BigInteger $y)
    {
        return gmp_cmp($this->value, $y->value);
    }
}
