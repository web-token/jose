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

use Jose\Component\Core\Util\Ecc\Crypto\Key\PrivateKey;
use Jose\Component\Core\Util\Ecc\Crypto\Key\PublicKey;
use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Math\ModularArithmetic;

/**
 * *********************************************************************
 * Copyright (C) 2012 Matyas Danter.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * ***********************************************************************
 */

/**
 * This class is where the elliptic curve arithmetic takes place.
 * The important methods are:
 * - add: adds two points according to ec arithmetic
 * - double: doubles a point on the ec field mod p
 * - mul: uses double and add to achieve multiplication The rest of the methods are there for supporting the ones above.
 */
class Point
{
    /**
     * @var Curve
     */
    private $curve;

    /**
     * @var ModularArithmetic
     */
    private $modAdapter;

    /**
     * @var \GMP
     */
    private $x;

    /**
     * @var \GMP
     */
    private $y;

    /**
     * @var \GMP
     */
    private $order;

    /**
     * @var bool
     */
    private $infinity = false;

    /**
     * Initialize a new instance.
     *
     * @param Curve $curve
     * @param \GMP    $x
     * @param \GMP    $y
     * @param \GMP    $order
     * @param bool    $infinity
     *
     * @throws \RuntimeException when either the curve does not contain the given coordinates or
     *                           when order is not null and P(x, y) * order is not equal to infinity
     */
    public function __construct(Curve $curve, \GMP $x, \GMP $y, ?\GMP $order = null, bool $infinity = false)
    {
        $this->modAdapter = $curve->getModAdapter();
        $this->curve = $curve;
        $this->x = $x;
        $this->y = $y;
        $this->order = null === $order ? gmp_init(0, 10) : $order;
        $this->infinity = (bool) $infinity;
        if (!$infinity && !$curve->contains($x, $y)) {
            throw new \RuntimeException('Curve '.$curve.' does not contain point ('.GmpMath::toString($x).', '.GmpMath::toString($y).')');
        }

        if (!is_null($order)) {
            $mul = $this->mul($order);
            if (!$mul->isInfinity()) {
                throw new \RuntimeException('SELF * ORDER MUST EQUAL INFINITY. ('.(string) $mul.' found instead)');
            }
        }
    }

    /**
     * @return bool
     */
    public function isInfinity(): bool
    {
        return (bool) $this->infinity;
    }

    /**
     * @return Curve
     */
    public function getCurve(): Curve
    {
        return $this->curve;
    }

    /**
     * @return \GMP
     */
    public function getOrder(): \GMP
    {
        return $this->order;
    }

    /**
     * @return \GMP
     */
    public function getX(): \GMP
    {
        return $this->x;
    }

    /**
     * @return \GMP
     */
    public function getY(): \GMP
    {
        return $this->y;
    }

    /**
     * @param Point $addend
     *
     * @return Point
     */
    public function add(Point $addend): Point
    {
        if (!$this->curve->equals($addend->getCurve())) {
            throw new \RuntimeException('The Elliptic Curves do not match.');
        }

        if ($addend->isInfinity()) {
            return clone $this;
        }

        if ($this->isInfinity()) {
            return clone $addend;
        }

        if (GmpMath::equals($addend->getX(), $this->x)) {
            if (GmpMath::equals($addend->getY(), $this->y)) {
                return $this->getDouble();
            } else {
                return $this->curve->getInfinity();
            }
        }

        $slope = $this->modAdapter->div(
            GmpMath::sub($addend->getY(), $this->y),
            GmpMath::sub($addend->getX(), $this->x)
        );

        $xR = $this->modAdapter->sub(
            GmpMath::sub(GmpMath::pow($slope, 2), $this->x),
            $addend->getX()
        );

        $yR = $this->modAdapter->sub(
            GmpMath::mul($slope, GmpMath::sub($this->x, $xR)),
            $this->y
        );

        return $this->curve->getPoint($xR, $yR, $this->order);
    }

    /**
     * @param Point $other
     *
     * @return int
     */
    public function cmp(Point $other): int
    {
        if ($other->isInfinity() && $this->isInfinity()) {
            return 0;
        }

        if ($other->isInfinity() || $this->isInfinity()) {
            return 1;
        }

        $equal = (GmpMath::equals($this->x, $other->getX()));
        $equal &= (GmpMath::equals($this->y, $other->getY()));
        $equal &= $this->isInfinity() == $other->isInfinity();
        $equal &= $this->curve->equals($other->getCurve());

        return $equal ? 0 : 1;
    }

    /**
     * @param Point $other
     *
     * @return bool
     */
    public function equals(Point $other): bool
    {
        return $this->cmp($other) === 0;
    }

    /**
     * @param \GMP $n
     *
     * @return Point
     */
    public function mul(\GMP $n): Point
    {
        if ($this->isInfinity()) {
            return $this->curve->getInfinity();
        }

        /** @var \GMP $zero */
        $zero = gmp_init(0, 10);
        if (GmpMath::cmp($this->order, $zero) > 0) {
            $n = GmpMath::mod($n, $this->order);
        }

        if (GmpMath::equals($n, $zero)) {
            return $this->curve->getInfinity();
        }

        /** @var Point[] $r */
        $r = [
            $this->curve->getInfinity(),
            clone $this,
        ];

        $k = $this->curve->getSize();
        $n = str_pad(GmpMath::baseConvert(GmpMath::toString($n), 10, 2), $k, '0', STR_PAD_LEFT);

        for ($i = 0; $i < $k; ++$i) {
            $j = $n[$i];

            $this->cswap($r[0], $r[1], $j ^ 1);

            $r[0] = $r[0]->add($r[1]);
            $r[1] = $r[1]->getDouble();

            $this->cswap($r[0], $r[1], $j ^ 1);
        }

        $r[0]->validate();

        return $r[0];
    }

    /**
     * @param \GMP $x
     * @param \GMP $y
     * @param \GMP $order
     *
     * @return PublicKey
     */
    public function getPublicKeyFrom(\GMP $x, \GMP $y, ?\GMP $order = null): PublicKey
    {
        $pubPoint = $this->getCurve()->getPoint($x, $y, $order);

        return new PublicKey($this->getOrder(), $pubPoint);
    }

    /**
     * @param \GMP $secret
     *
     * @return PrivateKey
     */
    public function getPrivateKeyFrom(\GMP $secret): PrivateKey
    {
        return new PrivateKey($secret);
    }

    /**
     * @param Point $a
     * @param Point $b
     * @param int   $cond
     */
    private function cswap(Point $a, Point $b, int $cond)
    {
        $this->cswapValue($a->x, $b->x, $cond);
        $this->cswapValue($a->y, $b->y, $cond);
        $this->cswapValue($a->order, $b->order, $cond);
        $this->cswapValue($a->infinity, $b->infinity, $cond);
    }

    /**
     * @param $a
     * @param $b
     * @param $cond
     */
    private function cswapValue(&$a, &$b, int $cond)
    {
        $isGMP = is_object($a) && $a instanceof \GMP;

        /** @var \GMP $sa */
        $sa = $isGMP ? $a : gmp_init(intval($a), 10);

        /** @var \GMP $sb */
        $sb = $isGMP ? $b : gmp_init(intval($b), 10);
        $size = max(mb_strlen(gmp_strval($sa, 2), '8bit'), mb_strlen(gmp_strval($sb, 2), '8bit'));

        $mask = 1 - intval($cond);
        $mask = str_pad('', $size, $mask, STR_PAD_LEFT);

        /** @var \GMP $mask */
        $mask = gmp_init($mask, 2);

        $taA = GmpMath::bitwiseAnd($sa, $mask);
        $taB = GmpMath::bitwiseAnd($sb, $mask);

        $sa = GmpMath::bitwiseXor(GmpMath::bitwiseXor($sa, $sb), $taB);
        $sb = GmpMath::bitwiseXor(GmpMath::bitwiseXor($sa, $sb), $taA);
        $sa = GmpMath::bitwiseXor(GmpMath::bitwiseXor($sa, $sb), $taB);

        $a = $isGMP ? $sa : (bool) gmp_strval($sa, 10);
        $b = $isGMP ? $sb : (bool) gmp_strval($sb, 10);
    }

    private function validate()
    {
        if (!$this->infinity && !$this->curve->contains($this->x, $this->y)) {
            throw new \RuntimeException('Invalid point');
        }
    }

    /**
     * @return Point
     */
    public function getDouble(): Point
    {
        if ($this->isInfinity()) {
            return $this->curve->getInfinity();
        }

        $modMath = $this->modAdapter;

        $a = $this->curve->getA();
        $threeX2 = GmpMath::mul(gmp_init(3, 10), GmpMath::pow($this->x, 2));

        $tangent = $modMath->div(
            GmpMath::add($threeX2, $a),
            GmpMath::mul(gmp_init(2, 10), $this->y)
        );

        $x3 = $modMath->sub(
            GmpMath::pow($tangent, 2),
            GmpMath::mul(gmp_init(2, 10), $this->x)
        );

        $y3 = $modMath->sub(
            GmpMath::mul($tangent, GmpMath::sub($this->x, $x3)),
            $this->y
        );

        return $this->curve->getPoint($x3, $y3, $this->order);
    }
}
