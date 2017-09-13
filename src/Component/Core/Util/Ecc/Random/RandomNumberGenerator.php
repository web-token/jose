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

    /**
     * @param \GMP $max
     * @return \GMP
     */
    public function generate(\GMP $max)
    {
        $numBits = NumberSize::bnNumBits($this->adapter, $max);
        $numBytes = ceil($numBits / 8);

        // Generate an integer of size >= $numBits
        $bytes = random_bytes($numBytes);
        $value = $this->adapter->stringToInt($bytes);

        $mask = gmp_sub(gmp_pow(2, $numBits), 1);
        $integer = gmp_and($value, $mask);

        return $integer;
    }
}
