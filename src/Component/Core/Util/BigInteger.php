<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util;

/**
 * Class BigInteger.
 */
final class BigInteger
{
    /**
     * Holds the BigInteger's value.
     *
     * @var \GMP
     */
    private $value;

    /**
     * @param \GMP $value
     */
    private function __construct(\GMP $value)
    {
        $this->value = $value;
    }

    /**
     * @param \GMP $value
     *
     * @return BigInteger
     */
    public static function createFromGMPResource(\GMP $value): BigInteger
    {
        return new self($value);
    }

    /**
     * @param string $value
     *
     * @return BigInteger
     */
    public static function createFromBinaryString(string $value): BigInteger
    {
        $value = '0x'.bin2hex($value);
        $value = gmp_init($value, 16);

        return new self($value);
    }

    /**
     * @param int $value
     *
     * @return BigInteger
     */
    public static function createFromDecimal(int $value): BigInteger
    {
        $value = gmp_init($value, 10);

        return new self($value);
    }

    /**
     * Converts a BigInteger to a binary string.
     *
     * @return string
     */
    public function toBytes(): string
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
     * Adds two BigIntegers.
     *
     *  @param BigInteger $y
     *
     *  @return BigInteger
     */
    public function add(BigInteger $y): BigInteger
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
    public function subtract(BigInteger $y): BigInteger
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
    public function multiply(BigInteger $x): BigInteger
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
    public function divide(BigInteger $x): BigInteger
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
    public function modPow(BigInteger $e, BigInteger $n): BigInteger
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
    public function mod(BigInteger $d): BigInteger
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
    public function modInverse(BigInteger $n): BigInteger
    {
        $value = gmp_invert($this->value, $n->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Compares two numbers.
     *
     * @param BigInteger $y
     *
     * @return int < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal
     */
    public function compare(BigInteger $y): int
    {
        return gmp_cmp($this->value, $y->value);
    }

    /**
     * @param BigInteger $y
     *
     * @return bool
     */
    public function equals(BigInteger $y): bool
    {
        return 0 === $this->compare($y);
    }

    /**
     * @param BigInteger $y
     *
     * @return BigInteger
     */
    public static function random(BigInteger $y): BigInteger
    {
        $zero = self::createFromDecimal(0);

        return self::createFromGMPResource(gmp_random_range($zero->value, $y->value));
    }

    /**
     * @param BigInteger $y
     *
     * @return BigInteger
     */
    public function gcd(BigInteger $y): BigInteger
    {
        return self::createFromGMPResource(gmp_gcd($this->value, $y->value));
    }

    /**
     * @param BigInteger $y
     *
     * @return bool
     */
    public function lowerThan(BigInteger $y): bool
    {
        return 0 > $this->compare($y);
    }

    /**
     * @return bool
     */
    public function isEven(): bool
    {
        $zero = self::createFromDecimal(0);
        $two = self::createFromDecimal(2);

        return $this->mod($two)->equals($zero);
    }
}
