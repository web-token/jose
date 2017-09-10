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

final class BinaryString
{
    /**
     * Multi-byte-safe string length calculation.
     *
     * @param string $str
     *
     * @return int
     */
    public static function length(string $str): int
    {
        return mb_strlen($str, '8bit');
    }
}
