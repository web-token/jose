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

class BigInteger
{
    const MONTGOMERY = 0;

    const BARRETT = 1;

    const POWEROF2 = 2;

    const CLASSIC = 3;

    const NONE = 4;

    /**#@+
     * Array constants
     *
     * Rather than create a thousands and thousands of new BigInteger objects in repeated function calls to add() and
     * multiply() or whatever, we'll just work directly on arrays, taking them in as parameters and returning them.
     *
     */
    /**
     * $result[self::VALUE] contains the value.
     */
    const VALUE = 0;
    /**
     * $result[self::SIGN] contains the sign.
     */
    const SIGN = 1;
    /**#@-*/

    /**#@+
     */
    /**
     * Cache constants.
     *
     * $cache[self::VARIABLE] tells us whether or not the cached data is still valid.
     */
    const VARIABLE = 0;
    /**
     * $cache[self::DATA] contains the cached data.
     */
    const DATA = 1;
    /**#@-*/

    /**
     * Karatsuba Cutoff.
     *
     * At what point do we switch between Karatsuba multiplication and schoolbook long multiplication?
     */
    const KARATSUBA_CUTOFF = 25;

    /**#@+
     * Static properties used by the pure-PHP implementation.
     *
     * @see __construct()
     */
    protected static $base;
    protected static $baseFull;
    protected static $maxDigit;
    protected static $msb;

    /**
     * $max10 in greatest $max10Len satisfying
     * $max10 = 10**$max10Len <= 2**$base.
     */
    protected static $max10;

    /**
     * $max10Len in greatest $max10Len satisfying
     * $max10 = 10**$max10Len <= 2**$base.
     */
    protected static $max10Len;
    protected static $maxDigit2;
    /**#@-*/

    /**
     * Holds the BigInteger's value.
     *
     * @var array
     */
    private $value;

    /**
     * Holds the BigInteger's magnitude.
     *
     * @var bool
     */
    private $is_negative = false;

    /**
     * Precision.
     */
    private $precision = -1;

    /**
     * Precision Bitmask.
     */
    private $bitmask = false;

    /**
     * Converts base-2, base-10, base-16, and binary strings (base-256) to BigIntegers.
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
     * @param $x base-10 number or base-$base number if $base set.
     * @param int $base
     *
     * @return \Jose\Util\BigInteger
     */
    public function __construct($x = 0, $base = 10)
    {
        if (extension_loaded('openssl') && !defined('MATH_BIGINTEGER_OPENSSL_DISABLE') && !defined('MATH_BIGINTEGER_OPENSSL_ENABLED')) {
            define('MATH_BIGINTEGER_OPENSSL_ENABLED', true);
        }

        switch (true) {
            case is_resource($x) && get_resource_type($x) == 'GMP integer':
                // PHP 5.6 switched GMP from using resources to objects
            case $x instanceof \GMP:
                $this->value = $x;

                return;
        }
        $this->value = gmp_init(0);

        // '0' counts as empty() but when the base is 256 '0' is equal to ord('0') or 48
        // '0' is the only value like this per http://php.net/empty
        if (empty($x) && (abs($base) != 256 || $x !== '0')) {
            return;
        }

        switch ($base) {
            case -256:
                if (ord($x[0]) & 0x80) {
                    $x = ~$x;
                    $this->is_negative = true;
                }
            case 256:
                $sign = $this->is_negative ? '-' : '';
                $this->value = gmp_init($sign.'0x'.bin2hex($x));

                if ($this->is_negative) {
                    $this->is_negative = false;
                    $temp = $this->add(new static('-1'));
                    $this->value = $temp->value;
                }
                break;
            case 16:
            case -16:
                if ($base > 0 && $x[0] == '-') {
                    $this->is_negative = true;
                    $x = substr($x, 1);
                }

                $x = preg_replace('#^(?:0x)?([A-Fa-f0-9]*).*#', '$1', $x);

                $is_negative = false;
                if ($base < 0 && hexdec($x[0]) >= 8) {
                    $this->is_negative = $is_negative = true;
                    $x = bin2hex(~hex2bin($x));
                }

            $temp = $this->is_negative ? '-0x'.$x : '0x'.$x;
            $this->value = gmp_init($temp);
            $this->is_negative = false;

                if ($is_negative) {
                    $temp = $this->add(new static('-1'));
                    $this->value = $temp->value;
                }
                break;
            case 10:
            case -10:
                // (?<!^)(?:-).*: find any -'s that aren't at the beginning and then any characters that follow that
                // (?<=^|-)0*: find any 0's that are preceded by the start of the string or by a - (ie. octals)
                // [^-0-9].*: find any non-numeric characters and then any characters that follow that
                $x = preg_replace('#(?<!^)(?:-).*|(?<=^|-)0*|[^-0-9].*#', '', $x);

                $this->value = gmp_init($x);
                break;
            case 2: // base-2 support originally implemented by Lluis Pamies - thanks!
            case -2:
                if ($base > 0 && $x[0] == '-') {
                    $this->is_negative = true;
                    $x = substr($x, 1);
                }

                $x = preg_replace('#^([01]*).*#', '$1', $x);
                $x = str_pad($x, strlen($x) + (3 * strlen($x)) % 4, 0, STR_PAD_LEFT);

                $str = '0x';
                while (strlen($x)) {
                    $part = substr($x, 0, 4);
                    $str .= dechex(bindec($part));
                    $x = substr($x, 4);
                }

                if ($this->is_negative) {
                    $str = '-'.$str;
                }

                $temp = new static($str, 8 * $base); // ie. either -16 or +16
                $this->value = $temp->value;
                $this->is_negative = $temp->is_negative;

                break;
            default:
                // base not supported, so we'll let $this == 0
        }
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
     * @param bool $twos_compliment
     *
     * @return string
     *
     */
    public function toBytes($twos_compliment = false)
    {
        if ($twos_compliment) {
            $comparison = $this->compare(new static());
            if ($comparison == 0) {
                return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
            }

            $temp = $comparison < 0 ? $this->add(new static(1)) : $this;
            $bytes = $temp->toBytes();

            if (empty($bytes)) { // eg. if the number we're trying to convert is -1
                $bytes = chr(0);
            }

            if (ord($bytes[0]) & 0x80) {
                $bytes = chr(0).$bytes;
            }

            return $comparison < 0 ? ~$bytes : $bytes;
        }

        if (gmp_cmp($this->value, gmp_init(0)) == 0) {
            return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
        }

        $temp = gmp_strval(gmp_abs($this->value), 16);
        $temp = (strlen($temp) & 1) ? '0'.$temp : $temp;
        $temp = hex2bin($temp);

        return $this->precision > 0 ?
            substr(str_pad($temp, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
            ltrim($temp, chr(0));
    }

    /**
     * Converts a BigInteger to a hex string (eg. base-16)).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\ger('65');
     *
     *    echo $a->toHex(); // outputs '41'
     * ?>
     * </code>
     *
     * @param bool $twos_compliment
     *
     * @return string
     *
     */
    public function toHex($twos_compliment = false)
    {
        return bin2hex($this->toBytes($twos_compliment));
    }

    /**
     * Converts a BigInteger to a bit string (eg. base-2).
     *
     * Negative numbers are saved as positive numbers, unless $twos_compliment is set to true, at which point, they're
     * saved as two's compliment.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\ger('65');
     *
     *    echo $a->toBits(); // outputs '1000001'
     * ?>
     * </code>
     *
     * @param bool $twos_compliment
     *
     * @return string
     *
     */
    public function toBits($twos_compliment = false)
    {
        $hex = $this->toHex($twos_compliment);
        $bits = '';
        for ($i = strlen($hex) - 8, $start = strlen($hex) & 7; $i >= $start; $i -= 8) {
            $bits = str_pad(decbin(hexdec(substr($hex, $i, 8))), 32, '0', STR_PAD_LEFT).$bits;
        }
        if ($start) { // hexdec('') == 0
            $bits = str_pad(decbin(hexdec(substr($hex, 0, $start))), 8, '0', STR_PAD_LEFT).$bits;
        }
        $result = $this->precision > 0 ? substr($bits, -$this->precision) : ltrim($bits, '0');

        if ($twos_compliment && $this->compare(new static()) > 0 && $this->precision <= 0) {
            return '0'.$result;
        }

        return $result;
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
     * @param \Jose\Util\Integer $y
     *
     * @return \Jose\Util\BigInteger
     *
     */
    public function add(BigInteger $y)
    {
        $temp = new static();
        $temp->value = gmp_add($this->value, $y->value);

        return $this->_normalize($temp);
    }

    /**
     * Performs addition.
     *
     * @param array $x_value
     * @param bool  $x_negative
     * @param array $y_value
     * @param bool  $y_negative
     *
     * @return array
     */
    private static function _add($x_value, $x_negative, $y_value, $y_negative)
    {
        $x_size = count($x_value);
        $y_size = count($y_value);

        if ($x_size == 0) {
            return [
                self::VALUE => $y_value,
                self::SIGN  => $y_negative,
            ];
        } elseif ($y_size == 0) {
            return [
                self::VALUE => $x_value,
                self::SIGN  => $x_negative,
            ];
        }

        // subtract, if appropriate
        if ($x_negative != $y_negative) {
            if ($x_value == $y_value) {
                return [
                    self::VALUE => [],
                    self::SIGN  => false,
                ];
            }

            $temp = self::_subtract($x_value, false, $y_value, false);
            $temp[self::SIGN] = self::_compare($x_value, false, $y_value, false) > 0 ?
                $x_negative : $y_negative;

            return $temp;
        }

        if ($x_size < $y_size) {
            $size = $x_size;
            $value = $y_value;
        } else {
            $size = $y_size;
            $value = $x_value;
        }

        $value[count($value)] = 0; // just in case the carry adds an extra digit

        $carry = 0;
        for ($i = 0, $j = 1; $j < $size; $i += 2, $j += 2) {
            $sum = $x_value[$j] * self::$baseFull + $x_value[$i] + $y_value[$j] * self::$baseFull + $y_value[$i] + $carry;
            $carry = $sum >= self::$maxDigit2; // eg. floor($sum / 2**52); only possible values (in any base) are 0 and 1
            $sum = $carry ? $sum - self::$maxDigit2 : $sum;

            $temp = self::$base === 26 ? intval($sum / 0x4000000) : ($sum >> 31);

            $value[$i] = (int) ($sum - self::$baseFull * $temp); // eg. a faster alternative to fmod($sum, 0x4000000)
            $value[$j] = $temp;
        }

        if ($j == $size) { // ie. if $y_size is odd
            $sum = $x_value[$i] + $y_value[$i] + $carry;
            $carry = $sum >= self::$baseFull;
            $value[$i] = $carry ? $sum - self::$baseFull : $sum;
            ++$i; // ie. let $i = $j since we've just done $value[$i]
        }

        if ($carry) {
            for (; $value[$i] == self::$maxDigit; ++$i) {
                $value[$i] = 0;
            }
            ++$value[$i];
        }

        return [
            self::VALUE => self::_trim($value),
            self::SIGN  => $x_negative,
        ];
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
     * @param \Jose\Util\Integer $y
     *
     * @return \Jose\Util\BigInteger
     *
     */
    public function subtract(BigInteger $y)
    {
        $temp = new static();
        $temp->value = gmp_sub($this->value, $y->value);

        return $this->_normalize($temp);
    }

    /**
     * Performs subtraction.
     *
     * @param array $x_value
     * @param bool  $x_negative
     * @param array $y_value
     * @param bool  $y_negative
     *
     * @return array
     */
    private static function _subtract($x_value, $x_negative, $y_value, $y_negative)
    {
        $x_size = count($x_value);
        $y_size = count($y_value);

        if ($x_size == 0) {
            return [
                self::VALUE => $y_value,
                self::SIGN  => !$y_negative,
            ];
        } elseif ($y_size == 0) {
            return [
                self::VALUE => $x_value,
                self::SIGN  => $x_negative,
            ];
        }

        // add, if appropriate (ie. -$x - +$y or +$x - -$y)
        if ($x_negative != $y_negative) {
            $temp = self::_add($x_value, false, $y_value, false);
            $temp[self::SIGN] = $x_negative;

            return $temp;
        }

        $diff = self::_compare($x_value, $x_negative, $y_value, $y_negative);

        if (!$diff) {
            return [
                self::VALUE => [],
                self::SIGN  => false,
            ];
        }

        // switch $x and $y around, if appropriate.
        if ((!$x_negative && $diff < 0) || ($x_negative && $diff > 0)) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_negative = !$x_negative;

            $x_size = count($x_value);
            $y_size = count($y_value);
        }

        // at this point, $x_value should be at least as big as - if not bigger than - $y_value

        $carry = 0;
        for ($i = 0, $j = 1; $j < $y_size; $i += 2, $j += 2) {
            $sum = $x_value[$j] * self::$baseFull + $x_value[$i] - $y_value[$j] * self::$baseFull - $y_value[$i] - $carry;
            $carry = $sum < 0; // eg. floor($sum / 2**52); only possible values (in any base) are 0 and 1
            $sum = $carry ? $sum + self::$maxDigit2 : $sum;

            $temp = self::$base === 26 ? intval($sum / 0x4000000) : ($sum >> 31);

            $x_value[$i] = (int) ($sum - self::$baseFull * $temp);
            $x_value[$j] = $temp;
        }

        if ($j == $y_size) { // ie. if $y_size is odd
            $sum = $x_value[$i] - $y_value[$i] - $carry;
            $carry = $sum < 0;
            $x_value[$i] = $carry ? $sum + self::$baseFull : $sum;
            ++$i;
        }

        if ($carry) {
            for (; !$x_value[$i]; ++$i) {
                $x_value[$i] = self::$maxDigit;
            }
            --$x_value[$i];
        }

        return [
            self::VALUE => self::_trim($x_value),
            self::SIGN  => $x_negative,
        ];
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
     * @param \Jose\Util\Integer $x
     *
     * @return \Jose\Util\BigInteger
     */
    public function multiply(BigInteger $x)
    {
        $temp = new static();
        $temp->value = gmp_mul($this->value, $x->value);

        return $this->_normalize($temp);
    }

    /**
     * Performs multiplication.
     *
     * @param array $x_value
     * @param bool  $x_negative
     * @param array $y_value
     * @param bool  $y_negative
     *
     * @return array
     */
    private static function _multiply($x_value, $x_negative, $y_value, $y_negative)
    {
        $x_length = count($x_value);
        $y_length = count($y_value);

        if (!$x_length || !$y_length) { // a 0 is being multiplied
            return [
                self::VALUE => [],
                self::SIGN  => false,
            ];
        }

        return [
            self::VALUE => min($x_length, $y_length) < 2 * self::KARATSUBA_CUTOFF ?
                self::_trim(self::_regularMultiply($x_value, $y_value)) :
                self::_trim(self::_karatsuba($x_value, $y_value)),
            self::SIGN => $x_negative != $y_negative,
        ];
    }

    /**
     * Performs long multiplication on two BigIntegers.
     *
     * Modeled after 'multiply' in MutableBigInteger.java.
     *
     * @param array $x_value
     * @param array $y_value
     *
     * @return array
     */
    private static function _regularMultiply($x_value, $y_value)
    {
        $x_length = count($x_value);
        $y_length = count($y_value);

        if (!$x_length || !$y_length) { // a 0 is being multiplied
            return [];
        }

        if ($x_length < $y_length) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_length = count($x_value);
            $y_length = count($y_value);
        }

        $product_value = self::_array_repeat(0, $x_length + $y_length);

        // the following for loop could be removed if the for loop following it
        // (the one with nested for loops) initially set $i to 0, but
        // doing so would also make the result in one set of unnecessary adds,
        // since on the outermost loops first pass, $product->value[$k] is going
        // to always be 0

        $carry = 0;

        for ($j = 0; $j < $x_length; ++$j) { // ie. $i = 0
            $temp = $x_value[$j] * $y_value[0] + $carry; // $product_value[$k] == 0
            $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
            $product_value[$j] = (int) ($temp - self::$baseFull * $carry);
        }

        $product_value[$j] = $carry;

        // the above for loop is what the previous comment was talking about.  the
        // following for loop is the "one with nested for loops"
        for ($i = 1; $i < $y_length; ++$i) {
            $carry = 0;

            for ($j = 0, $k = $i; $j < $x_length; ++$j, ++$k) {
                $temp = $product_value[$k] + $x_value[$j] * $y_value[$i] + $carry;
                $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
                $product_value[$k] = (int) ($temp - self::$baseFull * $carry);
            }

            $product_value[$k] = $carry;
        }

        return $product_value;
    }

    /**
     * Performs Karatsuba multiplication on two BigIntegers.
     *
     * See {@link http://en.wikipedia.org/wiki/Karatsuba_algorithm Karatsuba algorithm} and
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=120 MPM 5.2.3}.
     *
     * @param array $x_value
     * @param array $y_value
     *
     * @return array
     */
    private static function _karatsuba($x_value, $y_value)
    {
        $m = min(count($x_value) >> 1, count($y_value) >> 1);

        if ($m < self::KARATSUBA_CUTOFF) {
            return self::_regularMultiply($x_value, $y_value);
        }

        $x1 = array_slice($x_value, $m);
        $x0 = array_slice($x_value, 0, $m);
        $y1 = array_slice($y_value, $m);
        $y0 = array_slice($y_value, 0, $m);

        $z2 = self::_karatsuba($x1, $y1);
        $z0 = self::_karatsuba($x0, $y0);

        $z1 = self::_add($x1, false, $x0, false);
        $temp = self::_add($y1, false, $y0, false);
        $z1 = self::_karatsuba($z1[self::VALUE], $temp[self::VALUE]);
        $temp = self::_add($z2, false, $z0, false);
        $z1 = self::_subtract($z1, false, $temp[self::VALUE], false);

        $z2 = array_merge(array_fill(0, 2 * $m, 0), $z2);
        $z1[self::VALUE] = array_merge(array_fill(0, $m, 0), $z1[self::VALUE]);

        $xy = self::_add($z2, false, $z1[self::VALUE], $z1[self::SIGN]);
        $xy = self::_add($xy[self::VALUE], $xy[self::SIGN], $z0, false);

        return $xy[self::VALUE];
    }

    /**
     * Performs squaring.
     *
     * @param array $x
     *
     * @return array
     */
    private static function _square($x = false)
    {
        return count($x) < 2 * self::KARATSUBA_CUTOFF ?
            self::_trim(self::_baseSquare($x)) :
            self::_trim(self::_karatsubaSquare($x));
    }

    /**
     * Performs traditional squaring on two BigIntegers.
     *
     * Squaring can be done faster than multiplying a number by itself can be.  See
     * {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=7 HAC 14.2.4} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=141 MPM 5.3} for more information.
     *
     * @param array $value
     *
     * @return array
     */
    private static function _baseSquare($value)
    {
        if (empty($value)) {
            return [];
        }
        $square_value = self::_array_repeat(0, 2 * count($value));

        for ($i = 0, $max_index = count($value) - 1; $i <= $max_index; ++$i) {
            $i2 = $i << 1;

            $temp = $square_value[$i2] + $value[$i] * $value[$i];
            $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
            $square_value[$i2] = (int) ($temp - self::$baseFull * $carry);

            // note how we start from $i+1 instead of 0 as we do in multiplication.
            for ($j = $i + 1, $k = $i2 + 1; $j <= $max_index; ++$j, ++$k) {
                $temp = $square_value[$k] + 2 * $value[$j] * $value[$i] + $carry;
                $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
                $square_value[$k] = (int) ($temp - self::$baseFull * $carry);
            }

            // the following line can yield values larger 2**15.  at this point, PHP should switch
            // over to floats.
            $square_value[$i + $max_index + 1] = $carry;
        }

        return $square_value;
    }

    /**
     * Performs Karatsuba "squaring" on two BigIntegers.
     *
     * See {@link http://en.wikipedia.org/wiki/Karatsuba_algorithm Karatsuba algorithm} and
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=151 MPM 5.3.4}.
     *
     * @param array $value
     *
     * @return array
     */
    private static function _karatsubaSquare($value)
    {
        $m = count($value) >> 1;

        if ($m < self::KARATSUBA_CUTOFF) {
            return self::_baseSquare($value);
        }

        $x1 = array_slice($value, $m);
        $x0 = array_slice($value, 0, $m);

        $z2 = self::_karatsubaSquare($x1);
        $z0 = self::_karatsubaSquare($x0);

        $z1 = self::_add($x1, false, $x0, false);
        $z1 = self::_karatsubaSquare($z1[self::VALUE]);
        $temp = self::_add($z2, false, $z0, false);
        $z1 = self::_subtract($z1, false, $temp[self::VALUE], false);

        $z2 = array_merge(array_fill(0, 2 * $m, 0), $z2);
        $z1[self::VALUE] = array_merge(array_fill(0, $m, 0), $z1[self::VALUE]);

        $xx = self::_add($z2, false, $z1[self::VALUE], $z1[self::SIGN]);
        $xx = self::_add($xx[self::VALUE], $xx[self::SIGN], $z0, false);

        return $xx[self::VALUE];
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
     *
     * @param \Jose\Util\Integer $y
     *
     * @return array
     *
     */
    public function divide(BigInteger $y)
    {
        $quotient = new static();
        $remainder = new static();

        list($quotient->value, $remainder->value) = gmp_div_qr($this->value, $y->value);

        if (gmp_sign($remainder->value) < 0) {
            $remainder->value = gmp_add($remainder->value, gmp_abs($y->value));
        }

        return [$this->_normalize($quotient), $this->_normalize($remainder)];
    }

    /**
     * Divides a BigInteger by a regular integer.
     *
     * abc / x = a00 / x + b0 / x + c / x
     *
     * @param array $dividend
     * @param array $divisor
     *
     * @return array
     */
    private static function _divide_digit($dividend, $divisor)
    {
        $carry = 0;
        $result = [];

        for ($i = count($dividend) - 1; $i >= 0; --$i) {
            $temp = self::$baseFull * $carry + $dividend[$i];
            $result[$i] = self::_safe_divide($temp, $divisor);
            $carry = (int) ($temp - $divisor * $result[$i]);
        }

        return [$result, $carry];
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
     * @param \Jose\Util\Integer $e
     * @param \Jose\Util\Integer $n
     *
     * @return \Jose\Util\BigInteger
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
        $n = $this->bitmask !== false && $this->bitmask->compare($n) < 0 ? $this->bitmask : $n->abs();

        if ($e->compare(new static()) < 0) {
            $e = $e->abs();

            $temp = $this->modInverse($n);
            if ($temp === false) {
                return false;
            }

            return $this->_normalize($temp->modPow($e, $n));
        }

            $temp = new static();
            $temp->value = gmp_powm($this->value, $e->value, $n->value);

            return $this->_normalize($temp);
    }

    /**
     * Performs modular exponentiation.
     *
     * Alias for modPow().
     *
     * @param \Jose\Util\Integer $e
     * @param \Jose\Util\Integer $n
     *
     * @return \Jose\Util\BigInteger
     */
    public function powMod(BigInteger $e, BigInteger $n)
    {
        return $this->modPow($e, $n);
    }

    /**
     * Barrett Modular Reduction.
     *
     * See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=14 HAC 14.3.3} /
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=165 MPM 6.2.5} for more information.  Modified slightly,
     * so as not to require negative numbers (initially, this script didn't support negative numbers).
     *
     * Employs "folding", as described at
     * {@link http://www.cosic.esat.kuleuven.be/publications/thesis-149.pdf#page=66 thesis-149.pdf#page=66}.  To quote from
     * it, "the idea [behind folding] is to find a value x' such that x (mod m) = x' (mod m), with x' being smaller than x."
     *
     * Unfortunately, the "Barrett Reduction with Folding" algorithm described in thesis-149.pdf is not, as written, all that
     * usable on account of (1) its not using reasonable radix points as discussed in
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=162 MPM 6.2.2} and (2) the fact that, even with reasonable
     * radix points, it only works when there are an even number of digits in the denominator.  The reason for (2) is that
     * (x >> 1) + (x >> 1) != x / 2 + x / 2.  If x is even, they're the same, but if x is odd, they're not.  See the in-line
     * comments for details.
     *
     * @param array $n
     * @param array $m
     *
     * @return array
     */
    private static function _barrett($n, $m)
    {
        static $cache = [
            self::VARIABLE => [],
            self::DATA     => [],
        ];

        $m_length = count($m);

        // if (self::_compare($n, self::_square($m)) >= 0) {
        if (count($n) > 2 * $m_length) {
            $lhs = new static();
            $rhs = new static();
            $lhs->value = $n;
            $rhs->value = $m;
            list(, $temp) = $lhs->divide($rhs);

            return $temp->value;
        }

        // if (m.length >> 1) + 2 <= m.length then m is too small and n can't be reduced
        if ($m_length < 5) {
            return self::_regularBarrett($n, $m);
        }

        // n = 2 * m.length

        if (($key = array_search($m, $cache[self::VARIABLE])) === false) {
            $key = count($cache[self::VARIABLE]);
            $cache[self::VARIABLE][] = $m;

            $lhs = new static();
            $lhs_value = &$lhs->value;
            $lhs_value = self::_array_repeat(0, $m_length + ($m_length >> 1));
            $lhs_value[] = 1;
            $rhs = new static();
            $rhs->value = $m;

            list($u, $m1) = $lhs->divide($rhs);
            $u = $u->value;
            $m1 = $m1->value;

            $cache[self::DATA][] = [
                'u'  => $u, // m.length >> 1 (technically (m.length >> 1) + 1)
                'm1' => $m1, // m.length
            ];
        } else {
            extract($cache[self::DATA][$key]);
        }

        $cutoff = $m_length + ($m_length >> 1);
        $lsd = array_slice($n, 0, $cutoff); // m.length + (m.length >> 1)
        $msd = array_slice($n, $cutoff);    // m.length >> 1
        $lsd = self::_trim($lsd);
        $temp = self::_multiply($msd, false, $m1, false);
        $n = self::_add($lsd, false, $temp[self::VALUE], false); // m.length + (m.length >> 1) + 1

        if ($m_length & 1) {
            return self::_regularBarrett($n[self::VALUE], $m);
        }

        // (m.length + (m.length >> 1) + 1) - (m.length - 1) == (m.length >> 1) + 2
        $temp = array_slice($n[self::VALUE], $m_length - 1);
        // if even: ((m.length >> 1) + 2) + (m.length >> 1) == m.length + 2
        // if odd:  ((m.length >> 1) + 2) + (m.length >> 1) == (m.length - 1) + 2 == m.length + 1
        $temp = self::_multiply($temp, false, $u, false);
        // if even: (m.length + 2) - ((m.length >> 1) + 1) = m.length - (m.length >> 1) + 1
        // if odd:  (m.length + 1) - ((m.length >> 1) + 1) = m.length - (m.length >> 1)
        $temp = array_slice($temp[self::VALUE], ($m_length >> 1) + 1);
        // if even: (m.length - (m.length >> 1) + 1) + m.length = 2 * m.length - (m.length >> 1) + 1
        // if odd:  (m.length - (m.length >> 1)) + m.length     = 2 * m.length - (m.length >> 1)
        $temp = self::_multiply($temp, false, $m, false);

        // at this point, if m had an odd number of digits, we'd be subtracting a 2 * m.length - (m.length >> 1) digit
        // number from a m.length + (m.length >> 1) + 1 digit number.  ie. there'd be an extra digit and the while loop
        // following this comment would loop a lot (hence our calling _regularBarrett() in that situation).

        $result = self::_subtract($n[self::VALUE], false, $temp[self::VALUE], false);

        while (self::_compare($result[self::VALUE], $result[self::SIGN], $m, false) >= 0) {
            $result = self::_subtract($result[self::VALUE], $result[self::SIGN], $m, false);
        }

        return $result[self::VALUE];
    }

    /**
     * (Regular) Barrett Modular Reduction.
     *
     * For numbers with more than four digits BigInteger::_barrett() is faster.  The difference between that and this
     * is that this function does not fold the denominator into a smaller form.
     *
     * @param array $x
     * @param array $n
     *
     * @return array
     */
    private static function _regularBarrett($x, $n)
    {
        static $cache = [
            self::VARIABLE => [],
            self::DATA     => [],
        ];

        $n_length = count($n);

        if (count($x) > 2 * $n_length) {
            $lhs = new static();
            $rhs = new static();
            $lhs->value = $x;
            $rhs->value = $n;
            list(, $temp) = $lhs->divide($rhs);

            return $temp->value;
        }

        if (($key = array_search($n, $cache[self::VARIABLE])) === false) {
            $key = count($cache[self::VARIABLE]);
            $cache[self::VARIABLE][] = $n;
            $lhs = new static();
            $lhs_value = &$lhs->value;
            $lhs_value = self::_array_repeat(0, 2 * $n_length);
            $lhs_value[] = 1;
            $rhs = new static();
            $rhs->value = $n;
            list($temp) = $lhs->divide($rhs); // m.length
            $cache[self::DATA][] = $temp->value;
        }

        // 2 * m.length - (m.length - 1) = m.length + 1
        $temp = array_slice($x, $n_length - 1);
        // (m.length + 1) + m.length = 2 * m.length + 1
        $temp = self::_multiply($temp, false, $cache[self::DATA][$key], false);
        // (2 * m.length + 1) - (m.length - 1) = m.length + 2
        $temp = array_slice($temp[self::VALUE], $n_length + 1);

        // m.length + 1
        $result = array_slice($x, 0, $n_length + 1);
        // m.length + 1
        $temp = self::_multiplyLower($temp, false, $n, false, $n_length + 1);
        // $temp == array_slice(self::_multiply($temp, false, $n, false)->value, 0, $n_length + 1)

        if (self::_compare($result, false, $temp[self::VALUE], $temp[self::SIGN]) < 0) {
            $corrector_value = self::_array_repeat(0, $n_length + 1);
            $corrector_value[count($corrector_value)] = 1;
            $result = self::_add($result, false, $corrector_value, false);
            $result = $result[self::VALUE];
        }

        // at this point, we're subtracting a number with m.length + 1 digits from another number with m.length + 1 digits
        $result = self::_subtract($result, false, $temp[self::VALUE], $temp[self::SIGN]);
        while (self::_compare($result[self::VALUE], $result[self::SIGN], $n, false) > 0) {
            $result = self::_subtract($result[self::VALUE], $result[self::SIGN], $n, false);
        }

        return $result[self::VALUE];
    }

    /**
     * Performs long multiplication up to $stop digits.
     *
     * If you're going to be doing array_slice($product->value, 0, $stop), some cycles can be saved.
     *
     * @param array $x_value
     * @param bool  $x_negative
     * @param array $y_value
     * @param bool  $y_negative
     * @param int   $stop
     *
     * @return array
     */
    private static function _multiplyLower($x_value, $x_negative, $y_value, $y_negative, $stop)
    {
        $x_length = count($x_value);
        $y_length = count($y_value);

        if (!$x_length || !$y_length) { // a 0 is being multiplied
            return [
                self::VALUE => [],
                self::SIGN  => false,
            ];
        }

        if ($x_length < $y_length) {
            $temp = $x_value;
            $x_value = $y_value;
            $y_value = $temp;

            $x_length = count($x_value);
            $y_length = count($y_value);
        }

        $product_value = self::_array_repeat(0, $x_length + $y_length);

        // the following for loop could be removed if the for loop following it
        // (the one with nested for loops) initially set $i to 0, but
        // doing so would also make the result in one set of unnecessary adds,
        // since on the outermost loops first pass, $product->value[$k] is going
        // to always be 0

        $carry = 0;

        for ($j = 0; $j < $x_length; ++$j) { // ie. $i = 0, $k = $i
            $temp = $x_value[$j] * $y_value[0] + $carry; // $product_value[$k] == 0
            $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
            $product_value[$j] = (int) ($temp - self::$baseFull * $carry);
        }

        if ($j < $stop) {
            $product_value[$j] = $carry;
        }

        // the above for loop is what the previous comment was talking about.  the
        // following for loop is the "one with nested for loops"

        for ($i = 1; $i < $y_length; ++$i) {
            $carry = 0;

            for ($j = 0, $k = $i; $j < $x_length && $k < $stop; ++$j, ++$k) {
                $temp = $product_value[$k] + $x_value[$j] * $y_value[$i] + $carry;
                $carry = self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
                $product_value[$k] = (int) ($temp - self::$baseFull * $carry);
            }

            if ($k < $stop) {
                $product_value[$k] = $carry;
            }
        }

        return [
            self::VALUE => self::_trim($product_value),
            self::SIGN  => $x_negative != $y_negative,
        ];
    }

    /**
     * Montgomery Modular Reduction.
     *
     * ($x->_prepMontgomery($n))->_montgomery($n) yields $x % $n.
     * {@link http://math.libtomcrypt.com/files/tommath.pdf#page=170 MPM 6.3} provides insights on how this can be
     * improved upon (basically, by using the comba method).  gcd($n, 2) must be equal to one for this function
     * to work correctly.
     *
     * @param array $x
     * @param array $n
     *
     * @return array
     */
    private static function _montgomery($x, $n)
    {
        static $cache = [
            self::VARIABLE => [],
            self::DATA     => [],
        ];

        if (($key = array_search($n, $cache[self::VARIABLE])) === false) {
            $key = count($cache[self::VARIABLE]);
            $cache[self::VARIABLE][] = $x;
            $cache[self::DATA][] = self::_modInverse67108864($n);
        }

        $k = count($n);

        $result = [self::VALUE => $x];

        for ($i = 0; $i < $k; ++$i) {
            $temp = $result[self::VALUE][$i] * $cache[self::DATA][$key];
            $temp = $temp - self::$baseFull * (self::$base === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
            $temp = self::_regularMultiply([$temp], $n);
            $temp = array_merge($this->_array_repeat(0, $i), $temp);
            $result = self::_add($result[self::VALUE], false, $temp, false);
        }

        $result[self::VALUE] = array_slice($result[self::VALUE], $k);

        if (self::_compare($result, false, $n, false) >= 0) {
            $result = self::_subtract($result[self::VALUE], false, $n, false);
        }

        return $result[self::VALUE];
    }

    /**
     * Modular Inverse of a number mod 2**26 (eg. 67108864).
     *
     * Based off of the bnpInvDigit function implemented and justified in the following URL:
     *
     * {@link http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn.js}
     *
     * The following URL provides more info:
     *
     * {@link http://groups.google.com/group/sci.crypt/msg/7a137205c1be7d85}
     *
     * As for why we do all the bitmasking...  strange things can happen when converting from floats to ints. For
     * instance, on some computers, var_dump((int) -4294967297) yields int(-1) and on others, it yields
     * int(-2147483648).  To avoid problems stemming from this, we use bitmasks to guarantee that ints aren't
     * auto-converted to floats.  The outermost bitmask is present because without it, there's no guarantee that
     * the "residue" returned would be the so-called "common residue".  We use fmod, in the last step, because the
     * maximum possible $x is 26 bits and the maximum $result is 16 bits.  Thus, we have to be able to handle up to
     * 40 bits, which only 64-bit floating points will support.
     *
     * Thanks to Pedro Gimeno Fortea for input!
     *
     * @param array $x
     *
     * @return int
     */
    private function _modInverse67108864($x) // 2**26 == 67,108,864
    {
        $x = -$x[0];
        $result = $x & 0x3; // x**-1 mod 2**2
        $result = ($result * (2 - $x * $result)) & 0xF; // x**-1 mod 2**4
        $result = ($result * (2 - ($x & 0xFF) * $result))  & 0xFF; // x**-1 mod 2**8
        $result = ($result * ((2 - ($x & 0xFFFF) * $result) & 0xFFFF)) & 0xFFFF; // x**-1 mod 2**16
        $result = fmod($result * (2 - fmod($x * $result, self::$baseFull)), self::$baseFull); // x**-1 mod 2**26
        return $result & self::$maxDigit;
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
     * @param \Jose\Util\Integer $n
     *
     * @return \Jose\Util\eger|false
     *
     */
    public function modInverse(BigInteger $n)
    {
        $temp = new static();
        $temp->value = gmp_invert($this->value, $n->value);

        return ($temp->value === false) ? false : $this->_normalize($temp);
    }

    /**
     * Calculates the greatest common divisor and Bezout's identity.
     *
     * Say you have 693 and 609.  The GCD is 21.  Bezout's identity states that there exist integers x and y such that
     * 693*x + 609*y == 21.  In point of fact, there are actually an infinite number of x and y combinations and which
     * combination is returned is dependant upon which mode is in use.  See
     * {@link http://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity Bezout's identity - Wikipedia} for more information.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\eger(693);
     *    $b = new \Jose\Util\eger(609);
     *
     *    extract($a->extendedGCD($b));
     *
     *    echo $gcd->toString() . "\r\n"; // outputs 21
     *    echo $a->toString() * $x->toString() + $b->toString() * $y->toString(); // outputs 21
     * ?>
     * </code>
     *
     * @param \Jose\Util\Integer $n
     *
     * @return \Jose\Util\BigInteger
     *
     *    {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf#page=19 HAC 14.61}.  As the text above 14.61 notes,
     *    the more traditional algorithim requires "relatively costly multiple-precision divisions".
     */
    public function extendedGCD(BigInteger $n)
    {
        extract(gmp_gcdext($this->value, $n->value));

        return [
            'gcd' => $this->_normalize(new static($g)),
            'x'   => $this->_normalize(new static($s)),
            'y'   => $this->_normalize(new static($t)),
        ];
    }

    /**
     * Calculates the greatest common divisor.
     *
     * Say you have 693 and 609.  The GCD is 21.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \Jose\Util\eger(693);
     *    $b = new \Jose\Util\eger(609);
     *
     *    $gcd = a->extendedGCD($b);
     *
     *    echo $gcd->toString() . "\r\n"; // outputs 21
     * ?>
     * </code>
     *
     * @param \Jose\Util\Integer $n
     *
     * @return \Jose\Util\BigInteger
     */
    public function gcd(BigInteger $n)
    {
        extract($this->extendedGCD($n));

        return $gcd;
    }

    /**
     * Absolute value.
     *
     * @return \Jose\Util\BigInteger
     */
    public function abs()
    {
        $temp = new static();

        $temp->value = gmp_abs($this->value);

        return $temp;
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
     * @param \Jose\Util\Integer $y
     *
     * @return int < 0 if $this is less than $y; > 0 if $this is greater than $y, and 0 if they are equal.
     *
     */
    public function compare(BigInteger $y)
    {
        return gmp_cmp($this->value, $y->value);
    }

    /**
     * Compares two numbers.
     *
     * @param array $x_value
     * @param bool  $x_negative
     * @param array $y_value
     * @param bool  $y_negative
     *
     * @return int
     */
    private static function _compare($x_value, $x_negative, $y_value, $y_negative)
    {
        if ($x_negative != $y_negative) {
            return (!$x_negative && $y_negative) ? 1 : -1;
        }

        $result = $x_negative ? -1 : 1;

        if (count($x_value) != count($y_value)) {
            return (count($x_value) > count($y_value)) ? $result : -$result;
        }
        $size = max(count($x_value), count($y_value));

        $x_value = array_pad($x_value, $size, 0);
        $y_value = array_pad($y_value, $size, 0);

        for ($i = count($x_value) - 1; $i >= 0; --$i) {
            if ($x_value[$i] != $y_value[$i]) {
                return ($x_value[$i] > $y_value[$i]) ? $result : -$result;
            }
        }

        return 0;
    }

    /**
     * Tests the equality of two numbers.
     *
     * If you need to see if one number is greater than or less than another number, use BigInteger::compare()
     *
     * @param \Jose\Util\Integer $x
     *
     * @return bool
     */
    public function equals(BigInteger $x)
    {
        return gmp_cmp($this->value, $x->value) == 0;
    }

    /**
     * Set Precision.
     *
     * Some bitwise operations give different results depending on the precision being used.  Examples include left
     * shift, not, and rotates.
     *
     * @param int $bits
     */
    public function setPrecision($bits)
    {
        if ($bits < 1) {
            $this->precision = -1;
            $this->bitmask = false;

            return;
        }
        $this->precision = $bits;
        if (MATH_BIGINTEGER_MODE != self::MODE_BCMATH) {
            $this->bitmask = new static(chr((1 << ($bits & 0x7)) - 1).str_repeat(chr(0xFF), $bits >> 3), 256);
        } else {
            $this->bitmask = new static(bcpow('2', $bits, 0));
        }

        $temp = $this->_normalize($this);
        $this->value = $temp->value;
    }

    /**
     * Get Precision.
     *
     * @return int
     */
    public function getPrecision()
    {
        return $this->precision;
    }

    /**
     * Logical And.
     *
     * @param \Jose\Util\Integer $x
     *
     *
     * @return \Jose\Util\BigInteger
     */
    public function bitwise_and(BigInteger $x)
    {
        $temp = new static();
        $temp->value = gmp_and($this->value, $x->value);

        return $this->_normalize($temp);
    }

    /**
     * Logical Or.
     *
     * @param \Jose\Util\Integer $x
     *
     *
     * @return \Jose\Util\BigInteger
     */
    public function bitwise_or(BigInteger $x)
    {
                $temp = new static();
                $temp->value = gmp_or($this->value, $x->value);

                return $this->_normalize($temp);
    }

    /**
     * Logical Exclusive-Or.
     *
     * @param \Jose\Util\Integer $x
     *
     *
     * @return \Jose\Util\BigInteger
     */
    public function bitwise_xor(BigInteger $x)
    {
        $temp = new static();
        $temp->value = gmp_xor($this->value, $x->value);

        return $this->_normalize($temp);
    }

    /**
     * Logical Not.
     *
     *
     * @return \Jose\Util\BigInteger
     */
    public function bitwise_not()
    {
        // calculuate "not" without regard to $this->precision
        // (will always result in a smaller number.  ie. ~1 isn't 1111 1110 - it's 0)
        $temp = $this->toBytes();
        if ($temp == '') {
            return '';
        }
        $pre_msb = decbin(ord($temp[0]));
        $temp = ~$temp;
        $msb = decbin(ord($temp[0]));
        if (strlen($msb) == 8) {
            $msb = substr($msb, strpos($msb, '0'));
        }
        $temp[0] = chr(bindec($msb));

        // see if we need to add extra leading 1's
        $current_bits = strlen($pre_msb) + 8 * strlen($temp) - 8;
        $new_bits = $this->precision - $current_bits;
        if ($new_bits <= 0) {
            return $this->_normalize(new static($temp, 256));
        }

        // generate as many leading 1's as we need to.
        $leading_ones = chr((1 << ($new_bits & 0x7)) - 1).str_repeat(chr(0xFF), $new_bits >> 3);

        self::_base256_lshift($leading_ones, $current_bits);

        $temp = str_pad($temp, strlen($leading_ones), chr(0), STR_PAD_LEFT);

        return $this->_normalize(new static($leading_ones | $temp, 256));
    }

    /**
     * Logical Right Shift.
     *
     * Shifts BigInteger's by $shift bits, effectively dividing by 2**$shift.
     *
     * @param int $shift
     *
     * @return \Jose\Util\BigInteger
     *
     */
    public function bitwise_rightShift($shift)
    {
        $temp = new static();

        static $two;

        if (!isset($two)) {
            $two = gmp_init('2');
        }

        $temp->value = gmp_div_q($this->value, gmp_pow($two, $shift));

        return $this->_normalize($temp);
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
        $temp = new static();

        static $two;

        if (!isset($two)) {
            $two = gmp_init('2');
        }

        $temp->value = gmp_mul($this->value, gmp_pow($two, $shift));

        return $this->_normalize($temp);
    }

    /**
     * Logical Left Rotate.
     *
     * Instead of the top x bits being dropped they're appended to the shifted bit string.
     *
     * @param int $shift
     *
     * @return \Jose\Util\BigInteger
     */
    public function bitwise_leftRotate($shift)
    {
        $bits = $this->toBytes();

        if ($this->precision > 0) {
            $precision = $this->precision;
            if (MATH_BIGINTEGER_MODE == self::MODE_BCMATH) {
                $mask = $this->bitmask->subtract(new static(1));
                $mask = $mask->toBytes();
            } else {
                $mask = $this->bitmask->toBytes();
            }
        } else {
            $temp = ord($bits[0]);
            for ($i = 0; $temp >> $i; ++$i) {
            }
            $precision = 8 * strlen($bits) - 8 + $i;
            $mask = chr((1 << ($precision & 0x7)) - 1).str_repeat(chr(0xFF), $precision >> 3);
        }

        if ($shift < 0) {
            $shift += $precision;
        }
        $shift %= $precision;

        if (!$shift) {
            return clone $this;
        }

        $left = $this->bitwise_leftShift($shift);
        $left = $left->bitwise_and(new static($mask, 256));
        $right = $this->bitwise_rightShift($precision - $shift);
        $result = MATH_BIGINTEGER_MODE != self::MODE_BCMATH ? $left->bitwise_or($right) : $left->add($right);

        return $this->_normalize($result);
    }

    /**
     * Logical Right Rotate.
     *
     * Instead of the bottom x bits being dropped they're prepended to the shifted bit string.
     *
     * @param int $shift
     *
     * @return \Jose\Util\BigInteger
     */
    public function bitwise_rightRotate($shift)
    {
        return $this->bitwise_leftRotate(-$shift);
    }

    /**
     * Generates a random BigInteger.
     *
     * Byte length is equal to $length. Uses \phpseclib\Crypt\Random if it's loaded and mt_rand if it's not.
     *
     * @param int $length
     *
     * @return \Jose\Util\BigInteger
     */
    private static function _random_number_helper($size)
    {
        if (class_exists('\phpseclib\Crypt\Random')) {
            $random = random_bytes($size);
        } else {
            $random = '';

            if ($size & 1) {
                $random .= chr(mt_rand(0, 255));
            }

            $blocks = $size >> 1;
            for ($i = 0; $i < $blocks; ++$i) {
                // mt_rand(-2147483648, 0x7FFFFFFF) always produces -2147483648 on some systems
                $random .= pack('n', mt_rand(0, 0xFFFF));
            }
        }

        return new static($random, 256);
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
     * @param \Jose\Util\eger $arg1
     * @param \Jose\Util\eger $arg2
     *
     * @return \Jose\Util\BigInteger
     */
    public static function random(BigInteger $min, BigInteger $max)
    {
        $compare = $max->compare($min);

        if (!$compare) {
            return $this->_normalize($min);
        } elseif ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        static $one;
        if (!isset($one)) {
            $one = new static(1);
        }

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
        $random_max = new static(chr(1).str_repeat("\0", $size), 256);
        $random = static::_random_number_helper($size);

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

    /**
     * Generate a random prime number.
     *
     * If there's not a prime within the given range, false will be returned.
     * If more than $timeout seconds have elapsed, give up and return false.
     *
     * @param \Jose\Util\teger $min
     * @param \Jose\Util\teger $max
     * @param int              $timeout
     *
     * @return Math_BigInteger|false
     *
     */
    public static function randomPrime(BigInteger $min, BigInteger $max, $timeout = false)
    {
        $compare = $max->compare($min);

        if (!$compare) {
            return $min->isPrime() ? $min : false;
        } elseif ($compare < 0) {
            // if $min is bigger then $max, swap $min and $max
            $temp = $max;
            $max = $min;
            $min = $temp;
        }

        static $one, $two;
        if (!isset($one)) {
            $one = new static(1);
            $two = new static(2);
        }

        $start = time();

        $x = self::random($min, $max);

        // gmp_nextprime() requires PHP 5 >= 5.2.0 per <http://php.net/gmp-nextprime>.
        if (MATH_BIGINTEGER_MODE == self::MODE_GMP && extension_loaded('gmp')) {
            $p = new static();
            $p->value = gmp_nextprime($x->value);

            if ($p->compare($max) <= 0) {
                return $p;
            }

            if (!$min->equals($x)) {
                $x = $x->subtract($one);
            }

            return self::randomPrime($min, $x);
        }

        if ($x->equals($two)) {
            return $x;
        }

        $x->_make_odd();
        if ($x->compare($max) > 0) {
            // if $x > $max then $max is even and if $min == $max then no prime number exists between the specified range
            if ($min->equals($max)) {
                return false;
            }
            $x = clone $min;
            $x->_make_odd();
        }

        $initial_x = clone $x;

        while (true) {
            if ($timeout !== false && time() - $start > $timeout) {
                return false;
            }

            if ($x->isPrime()) {
                return $x;
            }

            $x = $x->add($two);

            if ($x->compare($max) > 0) {
                $x = clone $min;
                if ($x->equals($two)) {
                    return $x;
                }
                $x->_make_odd();
            }

            if ($x->equals($initial_x)) {
                return false;
            }
        }
    }

    /**
     * Make the current number odd.
     *
     * If the current number is odd it'll be unchanged.  If it's even, one will be added to it.
     */
    private function _make_odd()
    {
        switch (MATH_BIGINTEGER_MODE) {
            case self::MODE_GMP:
                gmp_setbit($this->value, 0);
                break;
            case self::MODE_BCMATH:
                if ($this->value[strlen($this->value) - 1] % 2 == 0) {
                    $this->value = bcadd($this->value, '1');
                }
                break;
            default:
                $this->value[0] |= 1;
        }
    }

    /**
     * Normalize.
     *
     * Removes leading zeros and truncates (if necessary) to maintain the appropriate precision
     *
     * @param \Jose\Util\BigInteger
     *
     * @return \Jose\Util\BigInteger
     */
    private function _normalize($result)
    {
        $result->precision = $this->precision;
        $result->bitmask = $this->bitmask;

        if ($this->bitmask !== false) {
            $result->value = gmp_and($result->value, $result->bitmask->value);
        }

        return $result;
    }

    /**
     * Trim.
     *
     * Removes leading zeros
     *
     * @param array $value
     *
     * @return \Jose\Util\BigInteger
     */
    private static function _trim($value)
    {
        for ($i = count($value) - 1; $i >= 0; --$i) {
            if ($value[$i]) {
                break;
            }
            unset($value[$i]);
        }

        return $value;
    }

    /**
     * Array Repeat.
     *
     * @param $input Array
     * @param $multiplier mixed
     *
     * @return array
     */
    private static function _array_repeat($input, $multiplier)
    {
        return ($multiplier) ? array_fill(0, $multiplier, $input) : [];
    }

    /**
     * Logical Left Shift.
     *
     * Shifts binary strings $shift bits, essentially multiplying by 2**$shift.
     *
     * @param $x String
     * @param $shift Integer
     *
     * @return string
     */
    private static function _base256_lshift(&$x, $shift)
    {
        if ($shift == 0) {
            return;
        }

        $num_bytes = $shift >> 3; // eg. floor($shift/8)
        $shift &= 7; // eg. $shift % 8

        $carry = 0;
        for ($i = strlen($x) - 1; $i >= 0; --$i) {
            $temp = ord($x[$i]) << $shift | $carry;
            $x[$i] = chr($temp);
            $carry = $temp >> 8;
        }
        $carry = ($carry != 0) ? chr($carry) : '';
        $x = $carry.$x.str_repeat(chr(0), $num_bytes);
    }

    /**
     * Single digit division.
     *
     * Even if int64 is being used the division operator will return a float64 value
     * if the dividend is not evenly divisible by the divisor. Since a float64 doesn't
     * have the precision of int64 this is a problem so, when int64 is being used,
     * we'll guarantee that the dividend is divisible by first subtracting the remainder.
     *
     * @param int $x
     * @param int $y
     *
     * @return int
     */
    private static function _safe_divide($x, $y)
    {
        if (self::$base === 26) {
            return (int) ($x / $y);
        }

        // self::$base === 31
        return ($x - ($x % $y)) / $y;
    }
}
