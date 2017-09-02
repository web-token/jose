<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Signature\SignatureAlgorithmInterface;
use Jose\Component\Signature\Util\RSA as JoseRSA;

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

        $pub = RSAKey::createFromJWK($key->toPublic());
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
        if (!$key->has('d')) {
            throw new \InvalidArgumentException('The key is not a private key.');
        }

        $priv = RSAKey::createFromJWK($key);
        if ($this->getSignatureMethod() === self::SIGNATURE_PSS) {
            $signature = JoseRSA::sign($priv, $input, $this->getAlgorithm());
            $result = is_string($signature);
        } else {
            $result = openssl_sign($input, $signature, $priv->toPEM(), $this->getAlgorithm());
        }
        if (false === $result) {
            throw new \InvalidArgumentException('An error occurred during the creation of the signature.');
        }

        return $signature;
    }

    /**
     * @param JWK $key
     */
    private function checkKey(JWK $key)
    {
        if ('RSA' !== $key->get('kty')) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        foreach (['n', 'e'] as $k) {
            if (!$key->has($k)) {
                throw new \InvalidArgumentException(sprintf('The key parameter "%s" is missing.', $k));
            }
        }
    }
}
