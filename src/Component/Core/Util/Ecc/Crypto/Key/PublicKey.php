<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util\Ecc\Crypto\Key;

/*
 * *********************************************************************
 * Copyright (C) 2012 Matyas Danter
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

use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Primitives\GeneratorPoint;
use Jose\Component\Core\Util\Ecc\Primitives\Point;

/**
 * This class serves as public- private key exchange for signature verification.
 */
final class PublicKey
{
    /**
     * @var Point
     */
    private $point;

    /**
     * Initialize a new instance.
     *
     * @param GeneratorPoint $generator
     * @param Point          $point
     *
     * @throws \LogicException
     * @throws \RuntimeException
     */
    public function __construct(GeneratorPoint $generator, Point $point)
    {
        $this->point = $point;
        $adapter = new GmpMath();

        $n = $generator->getOrder();

        if ($adapter->cmp($point->getX(), gmp_init(0, 10)) < 0 || $adapter->cmp($n, $point->getX()) <= 0
            || $adapter->cmp($point->getY(), gmp_init(0, 10)) < 0 || $adapter->cmp($n, $point->getY()) <= 0
        ) {
            throw new \RuntimeException('Generator point has x and y out of range.');
        }
    }

    /**
     * @return Point
     */
    public function getPoint(): Point
    {
        return $this->point;
    }
}
