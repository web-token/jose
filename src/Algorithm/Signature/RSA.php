<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

use Assert\Assertion;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\KeyConverter\RSAKey;
use Jose\Object\JWK;
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


        if ($this->getSignatureMethod() === self::SIGNATURE_PSS) {
            $pub = new JWK(RSAKey::toPublic(new RSAKey($key))->toArray());
            $rsa = $this->getRsaObject();
            $rsa->loadKey($pub);

            return $rsa->verify($input, $signature);
        } else {
            $pem = RSAKey::toPublic(new RSAKey($key))->toPEM();

            return 1 === openssl_verify($input, $signature, $pem, $this->getAlgorithm());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $input)
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The key is not a private key');


        if ($this->getSignatureMethod() === self::SIGNATURE_PSS) {
            $rsa = $this->getRsaObject();
            $rsa->loadKey($key);
            $result = $rsa->sign($input);
            Assertion::string($result, 'An error occurred during the creation of the signature');

            return $result;
        } else {
            $pem = (new RSAKey($key))->toPEM();
            $result = openssl_sign($input, $signature, $pem, $this->getAlgorithm());
            Assertion::true($result, 'Unable to sign');

            return $signature;
        }
    }

    /**
     * @param JWKInterface $key
     */
    private function checkKey(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'RSA', 'Wrong key type.');
    }

    /**
     * @return \Jose\Util\RSA
     */
    private function getRsaObject()
    {
        $rsa = new JoseRSA();
        $rsa->setHash($this->getAlgorithm());
        $rsa->setMGFHash($this->getAlgorithm());

        return $rsa;
    }
}
