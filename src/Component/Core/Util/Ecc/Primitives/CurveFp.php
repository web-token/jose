<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util\Ecc\Primitives;

use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Math\ModularArithmetic;

/**
 * This class is a representation of an EC over a field modulo a prime number.
 *
 * Important objectives for this class are:
 * - Does the curve contain a point?
 * - Comparison of two curves.
 */
final class CurveFp
{
    /**
     * @var CurveParameters
     */
    protected $parameters;

    /**
     * @var GmpMath
     */
    protected $adapter = null;

    /**
     * @var ModularArithmetic
     */
    protected $modAdapter = null;

    /**
     * Constructor that sets up the instance variables.
     *
     * @param CurveParameters $parameters
     * @param GmpMath         $adapter
     */
    public function __construct(CurveParameters $parameters, GmpMath $adapter)
    {
        $this->parameters = $parameters;
        $this->adapter = $adapter;
        $this->modAdapter = new ModularArithmetic($this->adapter, $this->parameters->getPrime());
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getModAdapter()
     */
    public function getModAdapter()
    {
        return $this->modAdapter;
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getPoint()
     */
    public function getPoint(\GMP $x, \GMP $y, \GMP $order = null)
    {
        return new Point($this->adapter, $this, $x, $y, $order);
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getInfinity()
     */
    public function getInfinity()
    {
        return new Point($this->adapter, $this, gmp_init(0, 10), gmp_init(0, 10), null, true);
    }

    public function getGenerator(\GMP $x, \GMP $y, \GMP $order)
    {
        return new GeneratorPoint($this->adapter, $this, $x, $y, $order);
    }

    /**
     * @param bool $wasOdd
     * @param \GMP $xCoord
     *
     * @return \GMP
     */
    public function recoverYfromX($wasOdd, \GMP $xCoord)
    {
        $math = $this->adapter;
        $prime = $this->getPrime();

        $root = $this->adapter->getNumberTheory()->squareRootModP(
            $math->add(
                $math->add(
                    $this->modAdapter->pow($xCoord, gmp_init(3, 10)),
                    $math->mul($this->getA(), $xCoord)
                ),
                $this->getB()
            ),
            $prime
        );

        if ($math->equals($math->mod($root, gmp_init(2, 10)), gmp_init(1)) === $wasOdd) {
            return $root;
        } else {
            return $math->sub($prime, $root);
        }
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::contains()
     */
    public function contains(\GMP $x, \GMP $y)
    {
        $math = $this->adapter;

        $eq_zero = $math->equals(
            $this->modAdapter->sub(
                $math->pow($y, 2),
                $math->add(
                    $math->add(
                        $math->pow($x, 3),
                        $math->mul($this->getA(), $x)
                    ),
                    $this->getB()
                )
            ),
            gmp_init(0, 10)
        );

        return $eq_zero;
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getA()
     */
    public function getA()
    {
        return $this->parameters->getA();
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getB()
     */
    public function getB()
    {
        return $this->parameters->getB();
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getPrime()
     */
    public function getPrime()
    {
        return $this->parameters->getPrime();
    }

    /**
     * @return int
     */
    public function getSize()
    {
        return $this->parameters->getSize();
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::cmp()
     */
    public function cmp(CurveFp $other)
    {
        $math = $this->adapter;

        $equal = $math->equals($this->getA(), $other->getA());
        $equal &= $math->equals($this->getB(), $other->getB());
        $equal &= $math->equals($this->getPrime(), $other->getPrime());

        return ($equal) ? 0 : 1;
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::equals()
     */
    public function equals(CurveFp $other)
    {
        return $this->cmp($other) == 0;
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::__toString()
     */
    public function __toString()
    {
        return 'curve('.$this->adapter->toString($this->getA()).', '.$this->adapter->toString($this->getB()).', '.$this->adapter->toString($this->getPrime()).')';
    }
}
