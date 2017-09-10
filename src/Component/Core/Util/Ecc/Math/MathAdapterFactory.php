<?php

namespace Jose\Component\Core\Util\Ecc\Math;

final class MathAdapterFactory
{
    /**
     * @return GmpMath
     */
    public static function getAdapter(): GmpMath
    {
        return new GmpMath();
    }
}
