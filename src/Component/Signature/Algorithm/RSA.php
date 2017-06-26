<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Algorithm;

use Assert\Assertion;
use Jose\Component\Signature\SignatureAlgorithmInterface;
use Jose\Component\KeyManagement\KeyConverter\RSAKey;
use Jose\Component\Core\JWK;
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
    abstract protected function getAlgorithm(): string;

    /**
     * @return int
     */
    abstract protected function getSignatureMethod(): int;

    /**
     * {@inheritdoc}
     */
    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);

        $pub = RSAKey::toPublic(new RSAKey($key));

        if ($this->getSignatureMethod() === self::SIGNATURE_PSS) {
            return JoseRSA::verify($pub, $input, $signature, $this->getAlgorithm());
        } else {
            return 1 === openssl_verify($input, $signature, $pub->toPEM(), $this->getAlgorithm());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The key is not a private key');

        $priv = new RSAKey($key);

        if ($this->getSignatureMethod() === self::SIGNATURE_PSS) {
            $signature = JoseRSA::sign($priv, $input, $this->getAlgorithm());
            $result = is_string($signature);
        } else {
            $result = openssl_sign($input, $signature, $priv->toPEM(), $this->getAlgorithm());
        }
        Assertion::true($result, 'An error occurred during the creation of the signature');

        return $signature;
    }

    /**
     * @param JWK $key
     */
    private function checkKey(JWK $key)
    {
        Assertion::eq($key->get('kty'), 'RSA', 'Wrong key type.');
    }
}