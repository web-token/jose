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
    private $parameters;

    /**
     * @var GmpMath
     */
    private $adapter;

    /**
     * @var ModularArithmetic
     */
    private $modAdapter;

    /**
     * Constructor that sets up the instance variables.
     *
     * @param CurveParameters $parameters
     */
    public function __construct(CurveParameters $parameters)
    {
        $this->parameters = $parameters;
        $this->adapter = new GmpMath();
        $this->modAdapter = new ModularArithmetic($this->parameters->getPrime());
    }

    /**
     * @return ModularArithmetic
     */
    public function getModAdapter(): ModularArithmetic
    {
        return $this->modAdapter;
    }

    /**
     * @param \GMP      $x
     * @param \GMP      $y
     * @param \GMP|null $order
     *
     * @return Point
     */
    public function getPoint(\GMP $x, \GMP $y, ?\GMP $order = null): Point
    {
        return new Point($this, $x, $y, $order);
    }

    /**
     * @return Point
     */
    public function getInfinity(): Point
    {
        return new Point($this, gmp_init(0, 10), gmp_init(0, 10), null, true);
    }

    /**
     * @param \GMP $x
     * @param \GMP $y
     * @param \GMP $order
     *
     * @return GeneratorPoint
     */
    public function getGenerator(\GMP $x, \GMP $y, \GMP $order): GeneratorPoint
    {
        return new GeneratorPoint($this, $x, $y, $order);
    }

    /**
     * @param \GMP $x
     * @param \GMP $y
     *
     * @return bool
     */
    public function contains(\GMP $x, \GMP $y): bool
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
     * @return \GMP
     */
    public function getA(): \GMP
    {
        return $this->parameters->getA();
    }

    /**
     * @return \GMP
     */
    public function getB(): \GMP
    {
        return $this->parameters->getB();
    }

    /**
     * @return \GMP
     */
    public function getPrime(): \GMP
    {
        return $this->parameters->getPrime();
    }

    /**
     * @return int
     */
    public function getSize(): int
    {
        return $this->parameters->getSize();
    }

    /**
     * @param CurveFp $other
     *
     * @return int
     */
    public function cmp(CurveFp $other): int
    {
        $math = $this->adapter;

        $equal = $math->equals($this->getA(), $other->getA());
        $equal &= $math->equals($this->getB(), $other->getB());
        $equal &= $math->equals($this->getPrime(), $other->getPrime());

        return $equal ? 0 : 1;
    }

    /**
     * @param CurveFp $other
     *
     * @return bool
     */
    public function equals(CurveFp $other): bool
    {
        return $this->cmp($other) === 0;
    }
}
