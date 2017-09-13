<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util\Ecc\Curves;

use Jose\Component\Core\Util\Ecc\Primitives\CurveFp;

final class CurveFactory
{
    /**
     * @param $name
     *
     * @return NamedCurveFp|CurveFp
     */
    public static function getCurveByName($name)
    {
        $nistFactory = self::getNistFactory();

        switch ($name) {
            case NistCurve::NAME_P192:
                return $nistFactory->curve192();
            case NistCurve::NAME_P224:
                return $nistFactory->curve224();
            case NistCurve::NAME_P256:
                return $nistFactory->curve256();
            case NistCurve::NAME_P384:
                return $nistFactory->curve384();
            case NistCurve::NAME_P521:
                return $nistFactory->curve521();
            default:
                throw new \RuntimeException('Unknown curve.');
        }
    }

    /**
     * @param $name
     *
     * @return \Jose\Component\Core\Util\Ecc\Primitives\GeneratorPoint
     */
    public static function getGeneratorByName($name)
    {
        $nistFactory = self::getNistFactory();

        switch ($name) {
            case NistCurve::NAME_P192:
                return $nistFactory->generator192();
            case NistCurve::NAME_P224:
                return $nistFactory->generator224();
            case NistCurve::NAME_P256:
                return $nistFactory->generator256();
            case NistCurve::NAME_P384:
                return $nistFactory->generator384();
            case NistCurve::NAME_P521:
                return $nistFactory->generator521();
            default:
                throw new \RuntimeException('Unknown generator.');
        }
    }

    /**
     * @return NistCurve
     */
    private static function getNistFactory(): NistCurve
    {
        return new NistCurve();
    }
}
