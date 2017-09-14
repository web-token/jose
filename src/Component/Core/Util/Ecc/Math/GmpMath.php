<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util\Ecc\Math;

final class GmpMath
{
    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return int
     */
    public function cmp(\GMP $first, \GMP $other): int
    {
        return gmp_cmp($first, $other);
    }

    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return bool
     */
    public function equals(\GMP $first, \GMP $other): bool
    {
        return gmp_cmp($first, $other) === 0;
    }

    /**
     * @param \GMP $number
     * @param \GMP $modulus
     *
     * @return \GMP
     */
    public function mod(\GMP $number, \GMP $modulus): \GMP
    {
        return gmp_mod($number, $modulus);
    }

    /**
     * @param \GMP $augend
     * @param \GMP $addend
     *
     * @return \GMP
     */
    public function add(\GMP $augend, \GMP $addend): \GMP
    {
        return gmp_add($augend, $addend);
    }

    /**
     * @param \GMP $minuend
     * @param \GMP $subtrahend
     *
     * @return \GMP
     */
    public function sub(\GMP $minuend, \GMP $subtrahend): \GMP
    {
        return gmp_sub($minuend, $subtrahend);
    }

    /**
     * @param \GMP $multiplier
     * @param \GMP $multiplicand
     *
     * @return \GMP
     */
    public function mul(\GMP $multiplier, \GMP $multiplicand): \GMP
    {
        return gmp_mul($multiplier, $multiplicand);
    }

    /**
     * @param \GMP $dividend
     * @param \GMP $divisor
     *
     * @return \GMP
     */
    public function div(\GMP $dividend, \GMP $divisor): \GMP
    {
        return gmp_div($dividend, $divisor);
    }

    /**
     * @param \GMP $base
     * @param $exponent
     *
     * @return \GMP
     */
    public function pow(\GMP $base, $exponent): \GMP
    {
        return gmp_pow($base, $exponent);
    }

    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return \GMP
     */
    public function bitwiseAnd(\GMP $first, \GMP $other): \GMP
    {
        return gmp_and($first, $other);
    }

    /**
     * @param \GMP $number
     * @param $positions
     *
     * @return \GMP
     */
    public function rightShift(\GMP $number, $positions): \GMP
    {
        // Shift 1 right = div / 2
        return gmp_div($number, gmp_pow(gmp_init(2, 10), $positions));
    }

    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return \GMP
     */
    public function bitwiseXor(\GMP $first, \GMP $other): \GMP
    {
        return gmp_xor($first, $other);
    }

    /**
     * @param \GMP $value
     *
     * @return string
     */
    public function toString(\GMP $value): string
    {
        return gmp_strval($value);
    }

    /**
     * @param $dec
     *
     * @return string
     */
    public function decHex($dec): string
    {
        $dec = gmp_init($dec, 10);

        if (gmp_cmp($dec, 0) < 0) {
            throw new \InvalidArgumentException('Unable to convert negative integer to string');
        }

        $hex = gmp_strval($dec, 16);

        if (mb_strlen($hex, '8bit') % 2 !== 0) {
            $hex = '0'.$hex;
        }

        return $hex;
    }

    /**
     * @param \GMP $base
     * @param \GMP $exponent
     * @param \GMP $modulus
     *
     * @return \GMP
     */
    public function powmod(\GMP $base, \GMP $exponent, \GMP $modulus): \GMP
    {
        if ($this->cmp($exponent, gmp_init(0, 10)) < 0) {
            throw new \InvalidArgumentException('Negative exponents ('.$this->toString($exponent).') not allowed.');
        }

        return gmp_powm($base, $exponent, $modulus);
    }

    /**
     * @param \GMP $a
     * @param \GMP $m
     *
     * @return \GMP
     */
    public function inverseMod(\GMP $a, \GMP $m): \GMP
    {
        return gmp_invert($a, $m);
    }

    /**
     * @param \GMP $a
     * @param \GMP $n
     *
     * @return int
     */
    public function jacobi(\GMP $a, \GMP $n): int
    {
        return gmp_jacobi($a, $n);
    }

    /**
     * @param $s
     *
     * @return \GMP
     */
    public function stringToInt($s): \GMP
    {
        $result = gmp_init(0, 10);
        $sLen = mb_strlen($s, '8bit');

        for ($c = 0; $c < $sLen; ++$c) {
            $result = gmp_add(gmp_mul(256, $result), gmp_init(ord($s[$c]), 10));
        }

        return $result;
    }

    /**
     * @param $number
     * @param $from
     * @param $to
     *
     * @return string
     */
    public function baseConvert($number, $from, $to): string
    {
        return gmp_strval(gmp_init($number, $from), $to);
    }

    /**
     * @return NumberTheory
     */
    public function getNumberTheory(): NumberTheory
    {
        return new NumberTheory();
    }

    /**
     * @param \GMP $modulus
     *
     * @return ModularArithmetic
     */
    public function getModularArithmetic(\GMP $modulus): ModularArithmetic
    {
        return new ModularArithmetic($modulus);
    }
}
