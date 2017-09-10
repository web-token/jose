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
