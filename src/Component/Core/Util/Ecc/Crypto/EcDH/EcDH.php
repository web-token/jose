<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util\Ecc\Crypto\EcDH;

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

use Jose\Component\Core\Util\Ecc\Crypto\Key\PrivateKey;
use Jose\Component\Core\Util\Ecc\Crypto\Key\PublicKey;
use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Primitives\Point;

/**
 * This class is the implementation of ECDH.
 * EcDH is safe key exchange and achieves
 * that a key is transported securely between two parties.
 * The key then can be hashed and used as a basis in
 * a dual encryption scheme, along with AES for faster
 * two- way encryption.
 */
final class EcDH
{
    /**
     * Adapter used for math calculations.
     *
     * @var GmpMath
     */
    private $adapter;

    /**
     * Secret key between the two parties.
     *
     * @var Point
     */
    private $secretKey = null;

    /**
     * @var PublicKey
     */
    private $recipientKey;

    /**
     * @var PrivateKey
     */
    private $senderKey;

    /**
     * EcDH constructor.
     */
    public function __construct()
    {
        $this->adapter = new GmpMath();
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\Crypto\EcDH\EcDH::calculateSharedKey()
     */
    public function calculateSharedKey()
    {
        $this->calculateKey();

        return $this->secretKey->getX();
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\Crypto\EcDH\EcDH::createMultiPartyKey()
     */
    public function createMultiPartyKey()
    {
        $this->calculateKey();

        return new PublicKey($this->adapter, $this->senderKey->getPoint(), $this->secretKey);
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\Crypto\EcDH\EcDH::setRecipientKey()
     */
    public function setRecipientKey(PublicKey $key = null)
    {
        $this->recipientKey = $key;

        return $this;
    }

    /**
     * @see \Jose\Component\Core\Util\Ecc\Crypto\EcDH\EcDH::setSenderKey()
     */
    public function setSenderKey(PrivateKey $key)
    {
        $this->senderKey = $key;

        return $this;
    }

    private function calculateKey()
    {
        $this->checkExchangeState();

        if ($this->secretKey === null) {
            $this->secretKey = $this->recipientKey->getPoint()->mul($this->senderKey->getSecret());
        }
    }

    /**
     * Verifies that the shared secret is known, or that the required keys are available
     * to calculate the shared secret.
     *
     * @throws \RuntimeException when the exchange has not been made
     */
    private function checkExchangeState()
    {
        if ($this->secretKey !== null) {
            return;
        }

        if ($this->senderKey === null) {
            throw new \RuntimeException('Sender key not set.');
        }

        if ($this->recipientKey === null) {
            throw new \RuntimeException('Recipient key not set.');
        }
    }
}
