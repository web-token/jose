<?php

namespace Jose\Component\Core\Util\Ecc\Random;

use Jose\Component\Core\Util\Ecc\Math\MathAdapterFactory;

final class RandomGeneratorFactory
{
    /**
     * @return RandomNumberGenerator
     */
    public static function getRandomGenerator()
    {
        return new RandomNumberGenerator(
            MathAdapterFactory::getAdapter()
        );
    }
}
