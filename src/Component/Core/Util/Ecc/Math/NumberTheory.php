<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util\Ecc\Math;

/***********************************************************************
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
     ************************************************************************/

/**
 * Implementation of some number theoretic algorithms.
 *
 * @author Matyas Danter
 */

/**
 * Rewritten to take a MathAdaptor to handle different environments. Has
 * some desireable functions for public key compression/recovery.
 */
final class NumberTheory
{
    /**
     * @var GmpMath
     */
    private $adapter;

    /**
     * NumberTheory constructor.
     */
    public function __construct()
    {
        $this->adapter = new GmpMath();
    }

    /**
     * @param \GMP[] $poly
     * @param \GMP[] $polymod
     * @param \GMP   $p
     *
     * @return \GMP[]
     */
    public function polynomialReduceMod(array $poly, array $polymod, \GMP $p): array
    {
        $adapter = $this->adapter;
        $count_polymod = count($polymod);
        if ($adapter->equals(end($polymod), gmp_init(1)) && $count_polymod > 1) {
            $zero = gmp_init(0);
            while (count($poly) >= $count_polymod) {
                if (!$adapter->equals(end($poly), $zero)) {
                    for ($i = 2; $i < $count_polymod + 1; ++$i) {
                        $poly[count($poly) - $i] =
                            $adapter->mod(
                                $adapter->sub(
                                    $poly[count($poly) - $i],
                                    $adapter->mul(
                                        end($poly),
                                        $polymod[$count_polymod - $i]
                                    )
                                ),
                                $p
                            );
                    }
                }

                $poly = array_slice($poly, 0, count($poly) - 1);
            }

            return $poly;
        }

        throw new \InvalidArgumentException('Unable to calculate polynomialReduceMod');
    }

    /**
     * @param \GMP[] $m1
     * @param \GMP[] $m2
     * @param \GMP[] $polymod
     * @param \GMP   $p
     *
     * @return array
     */
    public function polynomialMultiplyMod(array $m1, array $m2, array $polymod, \GMP $p): array
    {
        $prod = array();
        $cm1 = count($m1);
        $cm2 = count($m2);
        $zero = gmp_init(0, 10);

        for ($i = 0; $i < $cm1; ++$i) {
            for ($j = 0; $j < $cm2; ++$j) {
                $index = $i + $j;
                if (!isset($prod[$index])) {
                    $prod[$index] = $zero;
                }
                $prod[$index] =
                    $this->adapter->mod(
                        $this->adapter->add(
                            $prod[$index],
                            $this->adapter->mul(
                                $m1[$i],
                                $m2[$j]
                            )
                        ),
                        $p
                    );
            }
        }

        return $this->polynomialReduceMod($prod, $polymod, $p);
    }

    /**
     * @param array $base
     * @param \GMP  $exponent
     * @param array $polymod
     * @param \GMP  $p
     *
     * @return array|int
     */
    public function polynomialPowMod($base, \GMP $exponent, $polymod, \GMP $p)
    {
        $adapter = $this->adapter;
        $zero = gmp_init(0, 10);
        $one = gmp_init(1, 10);
        $two = gmp_init(2, 10);

        if ($adapter->cmp($exponent, $p) < 0) {
            if ($adapter->equals($exponent, $zero)) {
                return $one;
            }

            $G = $base;
            $k = $exponent;

            if ($adapter->equals($adapter->mod($k, $two), $one)) {
                $s = $G;
            } else {
                $s = array($one);
            }

            while ($adapter->cmp($k, $one) > 0) {
                $k = $adapter->div($k, $two);

                $G = $this->polynomialMultiplyMod($G, $G, $polymod, $p);
                if ($adapter->equals($adapter->mod($k, $two), $one)) {
                    $s = $this->polynomialMultiplyMod($G, $s, $polymod, $p);
                }
            }

            return $s;
        }

        throw new \InvalidArgumentException('Unable to calculate polynomialPowMod');
    }

    /**
     * @param \GMP $a
     * @param \GMP $p
     *
     * @return \GMP
     */
    public function squareRootModP(\GMP $a, \GMP $p)
    {
        $math = $this->adapter;
        $zero = gmp_init(0, 10);
        $one = gmp_init(1, 10);
        $two = gmp_init(2, 10);
        $four = gmp_init(4, 10);
        $eight = gmp_init(8, 10);

        $modMath = $math->getModularArithmetic($p);
        if ($math->cmp($one, $p) < 0) {
            if ($math->equals($a, $zero)) {
                return $zero;
            }

            if ($math->equals($p, $two)) {
                return $a;
            }

            $jac = $math->jacobi($a, $p);
            if ($jac == -1) {
                throw new \LogicException($math->toString($a).' has no square root modulo '.$math->toString($p));
            }

            if ($math->equals($math->mod($p, $four), gmp_init(3, 10))) {
                return $modMath->pow($a, $math->div($math->add($p, $one), $four));
            }

            if ($math->equals($math->mod($p, $eight), gmp_init(5, 10))) {
                $d = $modMath->pow($a, $math->div($math->sub($p, $one), $four));
                if ($math->equals($d, $one)) {
                    return $modMath->pow($a, $math->div($math->add($p, gmp_init(3, 10)), $eight));
                }

                if ($math->equals($d, $math->sub($p, $one))) {
                    return $modMath->mul(
                        $math->mul(
                            $two,
                            $a
                        ),
                        $modMath->pow(
                            $math->mul(
                                $four,
                                $a
                            ),
                            $math->div(
                                $math->sub(
                                    $p,
                                    gmp_init(5, 10)
                                ),
                                $eight
                            )
                        )
                    );
                }
                //shouldn't get here
            }

            for ($b = gmp_init(2, 10); $math->cmp($b, $p) < 0; $b = gmp_add($b, gmp_init(1, 10))) {
                if ($math->jacobi(
                    $math->sub(
                        $math->mul($b, $b),
                        $math->mul($four, $a)
                    ),
                    $p
                ) == -1
                ) {
                    $f = array($a, $math->sub($zero, $b), $one);

                    $ff = $this->polynomialPowMod(
                        array($zero, $one),
                        $math->div(
                            $math->add(
                                $p,
                                $one
                            ),
                            $two
                        ),
                        $f,
                        $p
                    );

                    if ($math->equals($ff[1], $zero)) {
                        return $ff[0];
                    }
                    // if we got here no b was found
                }
            }
        }

        throw new \InvalidArgumentException('Unable to calculate square root mod p!');
    }
}
