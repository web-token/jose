<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

use Assert\Assertion;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\KeyConverter\RSAKey;
use Jose\Object\JWKInterface;
use Jose\Util\RSA as JoseRSA;

/**
 * Class RSA.
 */
abstract class RSA implements SignatureAlgorithmInterface
{
    /**
     * Probabilistic Signature Scheme.
     */
    const SIGNATURE_PSS = 1;

    /**
     * Use the PKCS#1.
     */
    const SIGNATURE_PKCS1 = 2;

    /**
     * @return mixed
     */
    abstract protected function getAlgorithm();

    /**
     * @return mixed
     */
    abstract protected function getSignatureMethod();

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, $input, $signature)
    {
        $this->checkKey($key);

        $pub = RSAKey::toPublic(new RSAKey($key));

        if (self::SIGNATURE_PSS === $this->getSignatureMethod()) {
            return JoseRSA::verify($pub, $input, $signature, $this->getAlgorithm());
        } else {
            return 1 === openssl_verify($input, $signature, $pub->toPEM(), $this->getAlgorithm());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $input)
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The key is not a private key');

        $priv = new RSAKey($key);

        if (self::SIGNATURE_PSS === $this->getSignatureMethod()) {
            $signature = JoseRSA::sign($priv, $input, $this->getAlgorithm());
            $result = is_string($signature);
        } else {
            $result = openssl_sign($input, $signature, $priv->toPEM(), $this->getAlgorithm());
        }
        Assertion::true($result, 'An error occurred during the creation of the signature');

        return $signature;
    }

    /**
     * @param JWKInterface $key
     */
    private function checkKey(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'RSA', 'Wrong key type.');
    }
}
