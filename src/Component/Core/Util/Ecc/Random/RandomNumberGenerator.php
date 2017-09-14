<?php

namespace Jose\Component\Core\Util\Ecc\Random;

use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Util\NumberSize;

final class RandomNumberGenerator
{
    /**
     * @var GmpMath
     */
    private $adapter;

    /**
     * RandomNumberGenerator constructor.
     */
    public function __construct()
    {
        $this->adapter = new GmpMath();
    }
}
