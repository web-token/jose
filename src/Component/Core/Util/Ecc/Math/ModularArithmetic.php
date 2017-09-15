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

final class ModularArithmetic
{
    /**
     * @param \GMP $minuend
     * @param \GMP $subtrahend
     * @param \GMP $modulus
     *
     * @return \GMP
     */
    public static function sub(\GMP $minuend, \GMP $subtrahend, \GMP $modulus): \GMP
    {
        return GmpMath::mod(GmpMath::sub($minuend, $subtrahend), $modulus);
    }

    /**
     * @param \GMP $multiplier
     * @param \GMP $muliplicand
     * @param \GMP $modulus
     *
     * @return \GMP
     */
    public static function mul(\GMP $multiplier, \GMP $muliplicand, \GMP $modulus): \GMP
    {
        return GmpMath::mod(GmpMath::mul($multiplier, $muliplicand), $modulus);
    }

    /**
     * @param \GMP $dividend
     * @param \GMP $divisor
     * @param \GMP $modulus
     *
     * @return \GMP
     */
    public static function div(\GMP $dividend, \GMP $divisor, \GMP $modulus): \GMP
    {
        return self::mul($dividend, GmpMath::inverseMod($divisor, $modulus), $modulus);
    }
}
