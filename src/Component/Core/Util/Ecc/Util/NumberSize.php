<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util\Ecc\Util;

use Jose\Component\Core\Util\Ecc\Math\GmpMath;

final class NumberSize
{
    /**
     * Returns the number of bits used to store this number. Non-singicant upper bits are not counted.
     *
     * @param GmpMath $adapter
     * @param \GMP    $x
     *
     * @return number
     *
     * @see https://www.openssl.org/docs/crypto/BN_num_bytes.html
     */
    public static function bnNumBits(GmpMath $adapter, \GMP $x)
    {
        $zero = gmp_init(0, 10);
        if ($adapter->equals($x, $zero)) {
            return 0;
        }

        $log2 = 0;
        while (false === $adapter->equals($x, $zero)) {
            $x = $adapter->rightShift($x, 1);
            ++$log2;
        }

        return $log2;
    }
}
