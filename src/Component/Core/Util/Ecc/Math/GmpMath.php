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

use Jose\Component\Core\Util\Ecc\Util\BinaryString;

final class GmpMath
{
    /**
     * @see GmpMath::cmp()
     */
    public function cmp(\GMP $first, \GMP $other)
    {
        return gmp_cmp($first, $other);
    }

    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return bool
     */
    public function equals(\GMP $first, \GMP $other)
    {
        return gmp_cmp($first, $other) === 0;
    }

    /**
     * @see GmpMath::mod()
     */
    public function mod(\GMP $number, \GMP $modulus)
    {
        return gmp_mod($number, $modulus);
    }

    /**
     * @see GmpMath::add()
     */
    public function add(\GMP $augend, \GMP $addend)
    {
        return gmp_add($augend, $addend);
    }

    /**
     * @see GmpMath::sub()
     */
    public function sub(\GMP $minuend, \GMP $subtrahend)
    {
        return gmp_sub($minuend, $subtrahend);
    }

    /**
     * @see GmpMath::mul()
     */
    public function mul(\GMP $multiplier, \GMP $multiplicand)
    {
        return gmp_mul($multiplier, $multiplicand);
    }

    /**
     * @see GmpMath::div()
     */
    public function div(\GMP $dividend, \GMP $divisor)
    {
        return gmp_div($dividend, $divisor);
    }

    /**
     * @see GmpMath::pow()
     */
    public function pow(\GMP $base, $exponent)
    {
        return gmp_pow($base, $exponent);
    }

    /**
     * @see GmpMath::bitwiseAnd()
     */
    public function bitwiseAnd(\GMP $first, \GMP $other)
    {
        return gmp_and($first, $other);
    }

    /**
     * @see GmpMath::rightShift()
     */
    public function rightShift(\GMP $number, $positions)
    {
        // Shift 1 right = div / 2
        return gmp_div($number, gmp_pow(gmp_init(2, 10), $positions));
    }

    /**
     * @see GmpMath::bitwiseXor()
     */
    public function bitwiseXor(\GMP $first, \GMP $other)
    {
        return gmp_xor($first, $other);
    }

    /**
     * @see GmpMath::leftShift()
     */
    public function leftShift(\GMP $number, $positions)
    {
        // Shift 1 left = mul by 2
        return gmp_mul($number, gmp_pow(2, $positions));
    }

    /**
     * @see GmpMath::toString()
     */
    public function toString(\GMP $value)
    {
        return gmp_strval($value);
    }

    /**
     * @see GmpMath::hexDec()
     */
    public function hexDec($hex)
    {
        return gmp_strval(gmp_init($hex, 16), 10);
    }

    /**
     * @see GmpMath::decHex()
     */
    public function decHex($dec)
    {
        $dec = gmp_init($dec, 10);

        if (gmp_cmp($dec, 0) < 0) {
            throw new \InvalidArgumentException('Unable to convert negative integer to string');
        }

        $hex = gmp_strval($dec, 16);

        if (BinaryString::length($hex) % 2 != 0) {
            $hex = '0'.$hex;
        }

        return $hex;
    }

    /**
     * @see GmpMath::powmod()
     */
    public function powmod(\GMP $base, \GMP $exponent, \GMP $modulus)
    {
        if ($this->cmp($exponent, gmp_init(0, 10)) < 0) {
            throw new \InvalidArgumentException('Negative exponents ('.$this->toString($exponent).') not allowed.');
        }

        return gmp_powm($base, $exponent, $modulus);
    }

    /**
     * @see GmpMath::isPrime()
     */
    public function isPrime(\GMP $n)
    {
        $prob = gmp_prob_prime($n);

        if ($prob > 0) {
            return true;
        }

        return false;
    }

    /**
     * @see GmpMath::nextPrime()
     */
    public function nextPrime(\GMP $starting_value)
    {
        return gmp_nextprime($starting_value);
    }

    /**
     * @see GmpMath::inverseMod()
     */
    public function inverseMod(\GMP $a, \GMP $m)
    {
        return gmp_invert($a, $m);
    }

    /**
     * @see GmpMath::jacobi()
     */
    public function jacobi(\GMP $a, \GMP $n)
    {
        return gmp_jacobi($a, $n);
    }

    /**
     * @see GmpMath::intToString()
     */
    public function intToString(\GMP $x)
    {
        if (gmp_cmp($x, 0) < 0) {
            throw new \InvalidArgumentException('Unable to convert negative integer to string');
        }

        $hex = gmp_strval($x, 16);

        if (BinaryString::length($hex) % 2 != 0) {
            $hex = '0'.$hex;
        }

        return pack('H*', $hex);
    }

    /**
     * @see GmpMath::stringToInt()
     */
    public function stringToInt($s)
    {
        $result = gmp_init(0, 10);
        $sLen = BinaryString::length($s);

        for ($c = 0; $c < $sLen; ++$c) {
            $result = gmp_add(gmp_mul(256, $result), gmp_init(ord($s[$c]), 10));
        }

        return $result;
    }

    /**
     * @see GmpMath::digestInteger()
     */
    public function digestInteger(\GMP $m)
    {
        return $this->stringToInt(hash('sha1', $this->intToString($m), true));
    }

    /**
     * @see GmpMath::gcd2()
     */
    public function gcd2(\GMP $a, \GMP $b)
    {
        while ($this->cmp($a, gmp_init(0)) > 0) {
            $temp = $a;
            $a = $this->mod($b, $a);
            $b = $temp;
        }

        return $b;
    }

    /**
     * @see GmpMath::baseConvert()
     */
    public function baseConvert($number, $from, $to)
    {
        return gmp_strval(gmp_init($number, $from), $to);
    }

    /**
     * @see GmpMath::getNumberTheory()
     */
    public function getNumberTheory()
    {
        return new NumberTheory($this);
    }

    /**
     * @param \GMP $modulus
     *
     * @return ModularArithmetic
     */
    public function getModularArithmetic(\GMP $modulus)
    {
        return new ModularArithmetic($this, $modulus);
    }
}
