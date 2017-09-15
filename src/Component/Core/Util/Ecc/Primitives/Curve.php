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

use Jose\Component\Core\Util\Ecc\Crypto\Key\PublicKey;
use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Math\ModularArithmetic;

/**
 * This class is a representation of an EC over a field modulo a prime number.
 *
 * Important objectives for this class are:
 * - Does the curve contain a point?
 * - Comparison of two curves.
 */
final class Curve
{
    /**
     * Elliptic curve over the field of integers modulo a prime.
     *
     * @var \GMP
     */
    private $a;

    /**
     * @var \GMP
     */
    private $b;

    /**
     * @var \GMP
     */
    private $prime;

    /**
     * Binary length of keys associated with these curve parameters.
     *
     * @var int
     */
    private $size;

    /**
     * @var Point
     */
    private $generator;

    /**
     * @param int   $size
     * @param \GMP  $prime
     * @param \GMP  $a
     * @param \GMP  $b
     * @param Point $generator
     */
    public function __construct(int $size, \GMP $prime, \GMP $a, \GMP $b, Point $generator)
    {
        $this->size = $size;
        $this->prime = $prime;
        $this->a = $a;
        $this->b = $b;
        $this->generator = $generator;
    }

    /**
     * @return \GMP
     */
    public function getA(): \GMP
    {
        return $this->a;
    }

    /**
     * @return \GMP
     */
    public function getB(): \GMP
    {
        return $this->b;
    }

    /**
     * @return \GMP
     */
    public function getPrime(): \GMP
    {
        return $this->prime;
    }

    /**
     * @return int
     */
    public function getSize(): int
    {
        return $this->size;
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
        if (!$this->contains($x, $y)) {
            throw new \RuntimeException('Curve '.$this->__toString().' does not contain point ('.GmpMath::toString($x).', '.GmpMath::toString($y).')');
        }
        $point = Point::create($x, $y, $order);
        if (!is_null($order)) {
            $mul = $this->mul($point, $order);
            if (!$mul->isInfinity()) {
                throw new \RuntimeException('SELF * ORDER MUST EQUAL INFINITY. ('.(string) $mul.' found instead)');
            }
        }

        return $point;
    }

    /**
     * @param \GMP  $x
     * @param \GMP  $y
     *
     * @return PublicKey
     */
    public function getPublicKeyFrom(\GMP $x, \GMP $y): PublicKey
    {
        $point = $this->getPoint($x, $y);

        if (GmpMath::cmp($point->getX(), gmp_init(0, 10)) < 0 || GmpMath::cmp($this->generator->getOrder(), $point->getX()) <= 0
            || GmpMath::cmp($point->getY(), gmp_init(0, 10)) < 0 || GmpMath::cmp($this->generator->getOrder(), $point->getY()) <= 0
        ) {
            throw new \RuntimeException('Generator point has x and y out of range.');
        }


        return PublicKey::create($point);
    }

    /**
     * @param \GMP $x
     * @param \GMP $y
     *
     * @return bool
     */
    public function contains(\GMP $x, \GMP $y): bool
    {
        $eq_zero = GmpMath::equals(
            ModularArithmetic::sub(
                GmpMath::pow($y, 2),
                GmpMath::add(
                    GmpMath::add(
                        GmpMath::pow($x, 3),
                        GmpMath::mul($this->getA(), $x)
                    ),
                    $this->getB()
                ),
                $this->getPrime()
            ),
            gmp_init(0, 10)
        );

        return $eq_zero;
    }

    /**
     * @param Point $one
     * @param Point $two
     *
     * @return Point
     */
    public function add(Point $one, Point $two): Point
    {
        /*if (!$this->equals($two->getCurve())) {
            throw new \RuntimeException('The Elliptic Curves do not match.');
        }*/

        if ($two->isInfinity()) {
            return clone $one;
        }

        if ($one->isInfinity()) {
            return clone $two;
        }

        if (GmpMath::equals($two->getX(), $one->getX())) {
            if (GmpMath::equals($two->getY(), $one->getY())) {
                return $this->getDouble($one);
            } else {
                return Point::infinity();
            }
        }

        $slope = ModularArithmetic::div(
            GmpMath::sub($two->getY(), $one->getY()),
            GmpMath::sub($two->getX(), $one->getX()),
            $this->getPrime()
        );

        $xR = ModularArithmetic::sub(
            GmpMath::sub(GmpMath::pow($slope, 2), $one->getX()),
            $two->getX(),
            $this->getPrime()
        );

        $yR = ModularArithmetic::sub(
            GmpMath::mul($slope, GmpMath::sub($one->getX(), $xR)),
            $one->getY(),
            $this->getPrime()
        );

        return $this->getPoint($xR, $yR, $one->getOrder());
    }

    /**
     * @param Point $one
     * @param \GMP  $n
     *
     * @return Point
     */
    public function mul(Point $one, \GMP $n): Point
    {
        if ($one->isInfinity()) {
            return Point::infinity();
        }

        /** @var \GMP $zero */
        $zero = gmp_init(0, 10);
        if (GmpMath::cmp($one->getOrder(), $zero) > 0) {
            $n = GmpMath::mod($n, $one->getOrder());
        }

        if (GmpMath::equals($n, $zero)) {
            return Point::infinity();
        }

        /** @var Point[] $r */
        $r = [
            Point::infinity(),
            clone $one,
        ];

        $k = $this->getSize();
        $n = str_pad(GmpMath::baseConvert(GmpMath::toString($n), 10, 2), $k, '0', STR_PAD_LEFT);

        for ($i = 0; $i < $k; ++$i) {
            $j = $n[$i];

            Point::cswap($r[0], $r[1], $j ^ 1);

            $r[0] = $this->add($r[0],$r[1]);
            $r[1] = $this->getDouble($r[1]);

            Point::cswap($r[0], $r[1], $j ^ 1);
        }

        $this->validate($r[0]);

        return $r[0];
    }

    /**
     * @param Curve $other
     *
     * @return int
     */
    public function cmp(Curve $other): int
    {
        $equal = GmpMath::equals($this->getA(), $other->getA());
        $equal &= GmpMath::equals($this->getB(), $other->getB());
        $equal &= GmpMath::equals($this->getPrime(), $other->getPrime());

        return $equal ? 0 : 1;
    }

    /**
     * @param Curve $other
     *
     * @return bool
     */
    public function equals(Curve $other): bool
    {
        return $this->cmp($other) === 0;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return 'curve(' . GmpMath::toString($this->getA()) . ', ' . GmpMath::toString($this->getB()) . ', ' . GmpMath::toString($this->getPrime()) . ')';
    }

    /**
     * @param Point $point
     */
    private function validate(Point $point)
    {
        if (!$point->isInfinity() && !$this->contains($point->getX(), $point->getY())) {
            throw new \RuntimeException('Invalid point');
        }
    }

    /**
     * @param Point $point
     *
     * @return Point
     */
    public function getDouble(Point $point): Point
    {
        if ($point->isInfinity()) {
            return Point::infinity();
        }

        $a = $this->getA();
        $threeX2 = GmpMath::mul(gmp_init(3, 10), GmpMath::pow($point->getX(), 2));

        $tangent = ModularArithmetic::div(
            GmpMath::add($threeX2, $a),
            GmpMath::mul(gmp_init(2, 10), $point->getY()),
            $this->getPrime()
        );

        $x3 = ModularArithmetic::sub(
            GmpMath::pow($tangent, 2),
            GmpMath::mul(gmp_init(2, 10), $point->getX()),
            $this->getPrime()
        );

        $y3 = ModularArithmetic::sub(
            GmpMath::mul($tangent, GmpMath::sub($point->getX(), $x3)),
            $point->getY(),
            $this->getPrime()
        );

        return $this->getPoint($x3, $y3, $point->getOrder());
    }
}
