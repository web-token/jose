<?php

namespace Jose\Component\Core\Util\Ecc\Util;

final class BinaryString
{
    /**
     * Multi-byte-safe string length calculation
     *
     * @param string $str
     * @return int
     */
    public static function length(string $str): int
    {
        return mb_strlen($str, '8bit');
    }
}
