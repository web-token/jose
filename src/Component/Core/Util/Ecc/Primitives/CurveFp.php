<?php

/***********************************************************************
Copyright (C) 2012 Matyas Danter

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
 *************************************************************************/
namespace Jose\Component\Core\Util\Ecc\Primitives;

use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Math\ModularArithmetic;
use Jose\Component\Core\Util\Ecc\Random\RandomNumberGenerator;

/**
 * This class is a representation of an EC over a field modulo a prime number
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
     *
     * @var GmpMath
     */
    protected $adapter = null;

    /**
     *
     * @var ModularArithmetic
     */
    protected $modAdapter = null;

    /**
     * Constructor that sets up the instance variables.
     *
     * @param CurveParameters $parameters
     * @param GmpMath $adapter
     */
    public function __construct(CurveParameters $parameters, GmpMath $adapter)
    {
        $this->parameters = $parameters;
        $this->adapter = $adapter;
        $this->modAdapter = new ModularArithmetic($this->adapter, $this->parameters->getPrime());
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getModAdapter()
     */
    public function getModAdapter()
    {
        return $this->modAdapter;
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getPoint()
     */
    public function getPoint(\GMP $x, \GMP $y, \GMP $order = null)
    {
        return new Point($this->adapter, $this, $x, $y, $order);
    }
    
    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getInfinity()
     */
    public function getInfinity()
    {
        return new Point($this->adapter, $this, gmp_init(0, 10), gmp_init(0, 10), null, true);
    }

    /**
     * {@inheritDoc}
     */
    public function getGenerator(\GMP $x, \GMP $y, \GMP $order)
    {
        return new GeneratorPoint($this->adapter, $this, $x, $y, $order);
    }

    /**
     * @param bool $wasOdd
     * @param \GMP $xCoord
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
     * {@inheritDoc}
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
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getA()
     */
    public function getA()
    {
        return $this->parameters->getA();
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::getB()
     */
    public function getB()
    {
        return $this->parameters->getB();
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::cmp()
     */
    public function cmp(CurveFp $other)
    {
        $math = $this->adapter;

        $equal  = $math->equals($this->getA(), $other->getA());
        $equal &= $math->equals($this->getB(), $other->getB());
        $equal &= $math->equals($this->getPrime(), $other->getPrime());

        return ($equal) ? 0 : 1;
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::equals()
     */
    public function equals(CurveFp $other)
    {
        return $this->cmp($other) == 0;
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\CurveFp::__toString()
     */
    public function __toString()
    {
        return 'curve(' . $this->adapter->toString($this->getA()) . ', ' . $this->adapter->toString($this->getB()) . ', ' . $this->adapter->toString($this->getPrime()) . ')';
    }
}
