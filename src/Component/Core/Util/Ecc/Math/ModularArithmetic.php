<?php

namespace Jose\Component\Core\Util\Ecc\Math;

final class ModularArithmetic
{
    /**
     * @var GmpMath
     */
    private $adapter;

    /**
     * @var \GMP
     */
    private $modulus;

    /**
     * @param GmpMath $adapter
     * @param \GMP $modulus
     */
    public function __construct(GmpMath $adapter, \GMP $modulus)
    {
        $this->adapter = $adapter;
        $this->modulus = $modulus;
    }

    /**
     * @param \GMP $minuend
     * @param \GMP $subtrahend
     * @return \GMP
     */
    public function sub(\GMP $minuend, \GMP $subtrahend): \GMP
    {
        return $this->adapter->mod($this->adapter->sub($minuend, $subtrahend), $this->modulus);
    }

    /**
     * @param \GMP $multiplier
     * @param \GMP $muliplicand
     * @return \GMP
     */
    public function mul(\GMP $multiplier, \GMP $muliplicand): \GMP
    {
        return $this->adapter->mod($this->adapter->mul($multiplier, $muliplicand), $this->modulus);
    }

    /**
     * @param \GMP $dividend
     * @param \GMP $divisor
     * @return \GMP
     */
    public function div(\GMP $dividend, \GMP $divisor): \GMP
    {
        return $this->mul($dividend, $this->adapter->inverseMod($divisor, $this->modulus));
    }

    /**
     * @param \GMP $base
     * @param \GMP $exponent
     * @return \GMP
     */
    public function pow(\GMP $base, \GMP $exponent): \GMP
    {
        return $this->adapter->powmod($base, $exponent, $this->modulus);
    }
}
