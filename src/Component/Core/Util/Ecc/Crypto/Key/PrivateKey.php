<?php

namespace Jose\Component\Core\Util\Ecc\Crypto\Key;

/**
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

use Jose\Component\Core\Util\Ecc\Crypto\EcDH\EcDH;
use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Primitives\GeneratorPoint;

/**
 * This class serves as public - private key exchange for signature verification.
 */
final class PrivateKey
{
    /**
     * @var GeneratorPoint
     */
    private $generator;

    /**
     * @var \GMP
     */
    private $secretMultiplier;

    /**
     * @var GmpMath
     */
    private $adapter;

    /**
     * @param GmpMath $adapter
     * @param GeneratorPoint $generator
     * @param \GMP $secretMultiplier
     */
    public function __construct(GmpMath $adapter, GeneratorPoint $generator, \GMP $secretMultiplier)
    {
        $this->adapter = $adapter;
        $this->generator = $generator;
        $this->secretMultiplier = $secretMultiplier;
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\Crypto\Key\PrivateKey::getPublicKey()
     */
    public function getPublicKey()
    {
        return new PublicKey($this->adapter, $this->generator, $this->generator->mul($this->secretMultiplier));
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\Crypto\Key\PrivateKey::getPoint()
     */
    public function getPoint()
    {
        return $this->generator;
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\Crypto\Key\PrivateKey::getCurve()
     */
    public function getCurve()
    {
        return $this->generator->getCurve();
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\Crypto\Key\PrivateKey::getSecret()
     */
    public function getSecret()
    {
        return $this->secretMultiplier;
    }

    /**
     * {@inheritDoc}
     * @see \Jose\Component\Core\Util\Ecc\Crypto\Key\PrivateKey::createExchange()
     */
    public function createExchange(PublicKey $recipient = null)
    {
        $ecdh = new EcDH();
        $ecdh
            ->setSenderKey($this)
            ->setRecipientKey($recipient);

        return $ecdh;
    }
}
