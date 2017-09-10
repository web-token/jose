<?php

namespace Jose\Component\Core\Util\Ecc;

use Jose\Component\Core\Util\Ecc\Curves\NistCurve;
use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Math\MathAdapterFactory;

/**
 * Static factory class providing factory methods to work with NIST and SECG recommended curves.
 */
final class EccFactory
{
    /**
     * Selects and creates the most appropriate adapter for the running environment.
     *
     * @throws \RuntimeException
     * @return GmpMath
     */
    public static function getAdapter(): GmpMath
    {
        return MathAdapterFactory::getAdapter();
    }

    /**
     * Returns a factory to create NIST Recommended curves and generators.
     *
     * @return NistCurve
     */
    public static function getNistCurves(): NistCurve
    {
        return new NistCurve(self::getAdapter());
    }
}
