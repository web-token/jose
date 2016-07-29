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
     * @param mixed $value base-10 number or base-$base number if $base set.
     * @param int   $base
     */
    private function __construct($value = 0, $base = 10)
    {
        if ($value instanceof \GMP) {
            $this->value = $value;

            return;
        }

        $this->value = gmp_init(0);

        // '0' counts as empty() but when the base is 256 '0' is equal to ord('0') or 48
        // '0' is the only value like this per http://php.net/empty
        if (empty($value) && (abs($base) != 256 || $value !== '0')) {
            return;
        }

        if (256 === $base) {
            $value = '0x'.bin2hex($value);
            $base = 16;
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

        return new self($value);
    }

    /**
     * @param string $value
     * @param bool   $is_negative
     *
     * @return \Jose\Util\BigInteger
     */
    public static function createFromBinaryString($value, $is_negative = false)
    {
        Assertion::string($value);
        $value = '0x'.bin2hex($value);
        if (true === $is_negative) {
            $value = '-'.$value;
        }

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
     * Adds two BigIntegers.
     *
     * @param \Jose\Util\BigInteger $y
     *
     * @return \Jose\Util\BigInteger
     */
    public function add(BigInteger $y)
    {
        $value = gmp_add($this->value, $y->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Subtracts two BigIntegers.
     *
     * @param \Jose\Util\BigInteger $y
     *
     * @return \Jose\Util\BigInteger
     */
    public function subtract(BigInteger $y)
    {
        $value = gmp_sub($this->value, $y->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Multiplies two BigIntegers.
     *
     * @param \Jose\Util\BigInteger $x
     *
     * @return \Jose\Util\BigInteger
     */
    public function multiply(BigInteger $x)
    {
        $value = gmp_mul($this->value, $x->value);

        return self::createFromGMPResource($value);
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
        $n = $n->abs();

        if ($e->compare(self::createFromDecimalString('0')) < 0) {
            $e = $e->abs();

            $temp = $this->modInverse($n);
            if ($temp === false) {
                return false;
            }

            return $temp->modPow($e, $n);
        }

        $value = gmp_powm($this->value, $e->value, $n->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Calculates modular inverses.
     *
     * @param \Jose\Util\BigInteger $n
     *
     * @return \Jose\Util\BigInteger|bool
     */
    public function modInverse(BigInteger $n)
    {
        $value = gmp_invert($this->value, $n->value);

        return false === $value ? false : self::createFromGMPResource($value);
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

    /**
     * Logical Left Shift.
     *
     * @param int $shift
     *
     * @return \Jose\Util\BigInteger
     */
    public function bitwise_leftShift($shift)
    {
        $two = gmp_init('2');
        $value = gmp_mul($this->value, gmp_pow($two, $shift));

        return self::createFromGMPResource($value);
    }

    /**
     * Generates a random BigInteger.
     *
     * @param int $size
     *
     * @return \Jose\Util\BigInteger
     */
    private static function _random_number_helper($size)
    {
        return self::createFromBinaryString(random_bytes($size));
    }

    /**
     * Generate a random number.
     *
     * @param \Jose\Util\BigInteger $min
     * @param \Jose\Util\BigInteger $max
     *
     * @return \Jose\Util\BigInteger
     */
    public static function random(BigInteger $min, BigInteger $max)
    {
        $compare = $max->compare($min);

        if (!$compare) {
            return $min;
        } elseif ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        $one = self::createFromDecimalString('1');

        $max = $max->subtract($min->subtract($one));
        $size = strlen(ltrim($max->toBytes(), chr(0)));

        $random_max = self::createFromBinaryString(chr(1).str_repeat("\0", $size));
        $random = self::_random_number_helper($size);

        list($max_multiple) = $random_max->divide($max);
        $max_multiple = $max_multiple->multiply($max);

        while ($random->compare($max_multiple) >= 0) {
            $random = $random->subtract($max_multiple);
            $random_max = $random_max->subtract($max_multiple);
            $random = $random->bitwise_leftShift(8);
            $random = $random->add(self::_random_number_helper(1));
            $random_max = $random_max->bitwise_leftShift(8);
            list($max_multiple) = $random_max->divide($max);
            $max_multiple = $max_multiple->multiply($max);
        }
        list(, $random) = $random->divide($max);

        return $random->add($min);
    }
}
