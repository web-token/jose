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
     * If the second parameter - $base - is negative, then it will be assumed that the number's are encoded using
     * two's compliment.  The sole exception to this is -10, which is treated the same as 10 is.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\in base-16
     *
     *    echo $a->toString(); // outputs 50
     * ?>
     * </code>
     *
     * @param mixed $value    base-10 number or base-$base number if $base set.
     * @param int   $base
     */
    private function __construct($value = 0, $base = 10)
    {
        if($value instanceof \GMP) {
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
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\ger('65');
     *
     *    echo $a->toBytes(); // outputs chr(65)
     * ?>
     * </code>
     *
     * @return string
     *
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
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\ger('10');
     *    $b = new \Jose\Util\ger('20');
     *
     *    $c = $a->add($b);
     *
     *    echo $c->toString(); // outputs 30
     * ?>
     * </code>
     *
     * @param \Jose\Util\BigInteger $y
     *
     * @return \Jose\Util\BigInteger
     *
     */
    public function add(BigInteger $y)
    {
        $value = gmp_add($this->value, $y->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Subtracts two BigIntegers.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\ger('10');
     *    $b = new \Jose\Util\ger('20');
     *
     *    $c = $a->subtract($b);
     *
     *    echo $c->toString(); // outputs -10
     * ?>
     * </code>
     *
     * @param \Jose\Util\BigInteger $y
     *
     * @return \Jose\Util\BigInteger
     *
     */
    public function subtract(BigInteger $y)
    {
        $value = gmp_sub($this->value, $y->value);

        return self::createFromGMPResource($value);
    }

    /**
     * Multiplies two BigIntegers.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\ger('10');
     *    $b = new \Jose\Util\ger('20');
     *
     *    $c = $a->multiply($b);
     *
     *    echo $c->toString(); // outputs 200
     * ?>
     * </code>
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
     * Returns an array whose first element contains the quotient and whose second element contains the
     * "common residue".  If the remainder would be positive, the "common residue" and the remainder are the
     * same.  If the remainder would be negative, the "common residue" is equal to the sum of the remainder
     * and the divisor (basically, the "common residue" is the first positive modulo).
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\ger('10');
     *    $b = new \Jose\Util\ger('20');
     *
     *    list($quotient, $remainder) = $a->divide($b);
     *
     *    echo $quotient->toString(); // outputs 0
     *    echo "\r\n";
     *    echo $remainder->toString(); // outputs 10
     * ?>
     * </code>
     * @param \Jose\Util\BigInteger $y
     *
     * @return \Jose\Util\BigInteger[]
     *
     */
    public function divide(BigInteger $y)
    {
        list($quotient_value, $remainder_value) = gmp_div_qr($this->value, $y->value);

        if (gmp_sign($remainder_value) < 0) {
            $remainder_value = gmp_add($remainder_value, gmp_abs($y->value));
        }

        return [new self($quotient_value), new self($remainder_value)];
    }

    /**
     * Performs modular exponentiation.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\ger('10');
     *    $b = new \Jose\Util\ger('20');
     *    $c = new \Jose\Util\ger('30');
     *
     *    $c = $a->modPow($b, $c);
     *
     *    echo $c->toString(); // outputs 10
     * ?>
     * </code>
     *
     * @param \Jose\Util\BigInteger $e
     * @param \Jose\Util\BigInteger $n
     *
     * @return \Jose\Util\BigInteger|bool
     *
     *    and although the approach involving repeated squaring does vastly better, it, too, is impractical
     *    for our purposes.  The reason being that division - by far the most complicated and time-consuming
     *    of the basic operations (eg. +,-,*,/) - occurs multiple times within it.
     *
     *    Modular reductions resolve this issue.  Although an individual modular reduction takes more time
     *    then an individual division, when performed in succession (with the same modulo), they're a lot faster.
     *
     *    The two most commonly used modular reductions are Barrett and Montgomery reduction.  Montgomery reduction,
     *    although faster, only works when the gcd of the modulo and of the base being used is 1.  In RSA, when the
     *    base is a power of two, the modulo - a product of two primes - is always going to have a gcd of 1 (because
     *    the product of two odd numbers is odd), but what about when RSA isn't used?
     *
     *    In contrast, Barrett reduction has no such constraint.  As such, some bigint implementations perform a
     *    Barrett reduction after every operation in the modpow function.  Others perform Barrett reductions when the
     *    modulo is even and Montgomery reductions when the modulo is odd.  BigInteger.java's modPow method, however,
     *    uses a trick involving the Chinese Remainder Theorem to factor the even modulo into two numbers - one odd and
     *    the other, a power of two - and recombine them, later.  This is the method that this modPow function uses.
     *    {@link http://islab.oregonstate.edu/papers/j34monex.pdf Montgomery Reduction with Even Modulus} elaborates.
     */
    public function modPow(BigInteger $e, BigInteger $n)
    {
        $n = $n->abs();

        if ($e->compare(new self()) < 0) {
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
     * Say you have (30 mod 17 * x mod 17) mod 17 == 1.  x can be found using modular inverses.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\teger(30);
     *    $b = new \Jose\Util\teger(17);
     *
     *    $c = $a->modInverse($b);
     *    echo $c->toString(); // outputs 4
     *
     *    echo "\r\n";
     *
     *    $d = $a->multiply($c);
     *    list(, $d) = $d->divide($b);
     *    echo $d; // outputs 1 (as per the definition of modular inverse)
     * ?>
     * </code>
     *
     * @param \Jose\Util\BigInteger $n
     *
     * @return \Jose\Util\BigInteger|bool
     *
     */
    public function modInverse(BigInteger $n)
    {
        $value = gmp_invert($this->value, $n->value);

        return false === $value ? false : new self($value);
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
     * Although one might think !$x->compare($y) means $x != $y, it, in fact, means the opposite.  The reason for this is
     * demonstrated thusly:
     *
     * $x  > $y: $x->compare($y)  > 0
     * $x  < $y: $x->compare($y)  < 0
     * $x == $y: $x->compare($y) == 0
     *
     * Note how the same comparison operator is used.  If you want to test for equality, use $x->equals($y).
     *
     * @param \Jose\Util\BigInteger $y
     *
     * @return int < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal.
     *
     */
    public function compare(BigInteger $y)
    {
        return gmp_cmp($this->value, $y->value);
    }

    /**
     * Logical Left Shift.
     *
     * Shifts BigInteger's by $shift bits, effectively multiplying by 2**$shift.
     *
     * @param int $shift
     *
     * @return \Jose\Util\BigInteger
     *
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
     * Byte length is equal to $length. Uses \phpseclib\Crypt\Random if it's loaded and mt_rand if it's not.
     *
     * @param int $size
     *
     * @return \Jose\Util\BigInteger
     */
    private static function _random_number_helper($size)
    {
        return new self(random_bytes($size), 256);
    }

    /**
     * Generate a random number.
     *
     * Returns a random number between $min and $max where $min and $max
     * can be defined using one of the two methods:
     *
     * BigInteger::random($min, $max)
     * BigInteger::random($max, $min)
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

        $one = new self('1');

        $max = $max->subtract($min->subtract($one));
        $size = strlen(ltrim($max->toBytes(), chr(0)));

        /*
            doing $random % $max doesn't work because some numbers will be more likely to occur than others.
            eg. if $max is 140 and $random's max is 255 then that'd mean both $random = 5 and $random = 145
            would produce 5 whereas the only value of random that could produce 139 would be 139. ie.
            not all numbers would be equally likely. some would be more likely than others.

            creating a whole new random number until you find one that is within the range doesn't work
            because, for sufficiently small ranges, the likelihood that you'd get a number within that range
            would be pretty small. eg. with $random's max being 255 and if your $max being 1 the probability
            would be pretty high that $random would be greater than $max.

            phpseclib works around this using the technique described here:

            http://crypto.stackexchange.com/questions/5708/creating-a-small-number-from-a-cryptographically-secure-random-string
        */
        $random_max = new self(chr(1).str_repeat("\0", $size), 256);
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
