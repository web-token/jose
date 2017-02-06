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
     * @param resource $value
     *
     * @return BigInteger
     */
    public static function createFromGMPResource($value)
    {
        Assertion::isInstanceOf($value, \GMP::class);

        return new self($value, 0);
    }

    /**
     * @param string $value
     *
     * @return BigInteger
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
     * @return BigInteger
     */
    public static function createFromDecimalString($value)
    {
        Assertion::string($value);

        return new self($value, 10);
    }

    /**
     * @param int $value
     *
     * @return BigInteger
     */
    public static function createFromDecimal($value)
    {
        Assertion::integer($value);

        return new self($value, 10);
    }

    /**
     * Converts a BigInteger to a binary string.
     *
     * @return string
     */
    public function toBytes()
    {
        if (gmp_cmp($this->value, gmp_init(0)) === 0) {
            return '';
        }

        $temp = gmp_strval(gmp_abs($this->value), 16);
        $temp = mb_strlen($temp, '8bit') & 1 ? '0'.$temp : $temp;
        $temp = hex2bin($temp);

        return ltrim($temp, chr(0));
    }

    /**
     * Converts a BigInteger to a binary string.
     *
     * @return int
     */
    public function toInteger()
    {
        if (gmp_cmp($this->value, gmp_init(0)) === 0) {
            return '';
        }

        $temp = gmp_strval(gmp_abs($this->value), 10);

        return (int) $temp;
    }

    /**
     * Adds two BigIntegers.
     *
     *  @param BigInteger $y
     *
     *  @return BigInteger
     */
    public function add(BigInteger $y)
    {
        $value = gmp_add($this->value, $y->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Subtracts two BigIntegers.
     *
     *  @param BigInteger $y
     *
     *  @return BigInteger
     */
    public function subtract(BigInteger $y)
    {
        $value = gmp_sub($this->value, $y->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Multiplies two BigIntegers.
     *
     * @param BigInteger $x
     *
     *  @return BigInteger
     */
    public function multiply(BigInteger $x)
    {
        $value = gmp_mul($this->value, $x->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Divides two BigIntegers.
     *
     * @param BigInteger $x
     *
     *  @return BigInteger
     */
    public function divide(BigInteger $x)
    {
        $value = gmp_div($this->value, $x->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Performs modular exponentiation.
     *
     * @param BigInteger $e
     * @param BigInteger $n
     *
     * @return BigInteger
     */
    public function modPow(BigInteger $e, BigInteger $n)
    {
        $value = gmp_powm($this->value, $e->value, $n->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Performs modular exponentiation.
     *
     * @param BigInteger $d
     *
     * @return BigInteger
     */
    public function mod(BigInteger $d)
    {
        $value = gmp_mod($this->value, $d->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Calculates modular inverses.
     *
     * @param BigInteger $n
     *
     * @return BigInteger
     */
    public function modInverse(BigInteger $n)
    {
        $value = gmp_invert($this->value, $n->value);
        Assertion::isInstanceOf($value, \GMP::class);

        return self::createFromGMPResource($value);
    }

    /**
     * Compares two numbers.
     *
     * @param BigInteger $y
     *
     * @return int < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal.
     */
    public function compare(BigInteger $y)
    {
        return gmp_cmp($this->value, $y->value);
    }

    /**
     * @param BigInteger $y
     *
     * @return bool
     */
    public function equals(BigInteger $y)
    {
        return 0 === $this->compare($y);
    }

    /**
     * @param BigInteger $y
     *
     * @return BigInteger
     */
    public static function random(BigInteger $y)
    {
        $zero = BigInteger::createFromDecimal(0);

        return BigInteger::createFromGMPResource(gmp_random_range($zero->value, $y->value));
    }

    /**
     * @param BigInteger $y
     *
     * @return BigInteger
     */
    public function gcd(BigInteger $y)
    {
        return BigInteger::createFromGMPResource(gmp_gcd($this->value, $y->value));
    }

    /**
     * @param BigInteger $y
     *
     * @return bool
     */
    public function lowerThan(BigInteger $y)
    {
        return 0 > $this->compare($y);
    }

    /**
     * @param BigInteger $y
     *
     * @return bool
     */
    public function lowerOrEqualThan(BigInteger $y)
    {
        return 0 >= $this->compare($y);
    }

    /**
     * @param BigInteger $y
     *
     * @return bool
     */
    public function greaterThan(BigInteger $y)
    {
        return 0 < $this->compare($y);
    }

    /**
     * @param BigInteger $y
     *
     * @return bool
     */
    public function greaterOrEqualThan(BigInteger $y)
    {
        return 0 <= $this->compare($y);
    }

    /**
     * @return bool
     */
    public function isEven()
    {
        $zero = BigInteger::createFromDecimal(0);
        $two  = BigInteger::createFromDecimal(2);

        return $this->mod($two)->equals($zero);
    }

    /**
     * @return bool
     */
    public function isOdd()
    {
        return !$this->isEven();
    }
}
