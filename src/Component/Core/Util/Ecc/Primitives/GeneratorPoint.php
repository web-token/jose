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

/**
 * Curve point from which public and private keys can be derived.
 */
final class GeneratorPoint extends Point
{
    /**
     * @param CurveFp $curve
     * @param \GMP    $x
     * @param \GMP    $y
     * @param \GMP    $order
     */
    public function __construct(CurveFp $curve, \GMP $x, \GMP $y, \GMP $order)
    {
        parent::__construct($curve, $x, $y, $order);
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

        return new PublicKey($this, $pubPoint);
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
}
