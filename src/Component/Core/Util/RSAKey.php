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

namespace Jose\Component\Core\Util;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

final class RSAKey
{
    /**
     * @var array
     */
    private $values = [];

    /**
     * @var BigInteger
     */
    private $modulus;

    /**
     * @var int
     */
    private $modulus_length;

    /**
     * @var BigInteger
     */
    private $public_exponent;

    /**
     * @var BigInteger|null
     */
    private $private_exponent = null;

    /**
     * @var BigInteger[]
     */
    private $primes = [];

    /**
     * @var BigInteger[]
     */
    private $exponents = [];

    /**
     * @var BigInteger|null
     */
    private $coefficient = null;

    /**
     * @param JWK $data
     */
    private function __construct(JWK $data)
    {
        $this->loadJWK($data->all());
        $this->populateBigIntegers();
    }

    /**
     * @param JWK $jwk
     *
     * @return RSAKey
     */
    public static function createFromJWK(JWK $jwk): RSAKey
    {
        return new self($jwk);
    }

    /**
     * @return BigInteger
     */
    public function getModulus(): BigInteger
    {
        return $this->modulus;
    }

    /**
     * @return int
     */
    public function getModulusLength(): int
    {
        return $this->modulus_length;
    }

    /**
     * @return BigInteger
     */
    public function getExponent(): BigInteger
    {
        $d = $this->getPrivateExponent();
        if (null !== $d) {
            return $d;
        }

        return $this->getPublicExponent();
    }

    /**
     * @return BigInteger
     */
    public function getPublicExponent(): BigInteger
    {
        return $this->public_exponent;
    }

    /**
     * @return BigInteger|null
     */
    public function getPrivateExponent(): ?BigInteger
    {
        return $this->private_exponent;
    }

    /**
     * @return BigInteger[]
     */
    public function getPrimes(): array
    {
        return $this->primes;
    }

    /**
     * @return BigInteger[]
     */
    public function getExponents(): array
    {
        return $this->exponents;
    }

    /**
     * @return BigInteger|null
     */
    public function getCoefficient(): ?BigInteger
    {
        return $this->coefficient;
    }

    /**
     * @return bool
     */
    public function isPublic(): bool
    {
        return !array_key_exists('d', $this->values);
    }

    /**
     * @param RSAKey $private
     *
     * @return RSAKey
     */
    public static function toPublic(RSAKey $private): RSAKey
    {
        $data = $private->toArray();
        $keys = ['p', 'd', 'q', 'dp', 'dq', 'qi'];
        foreach ($keys as $key) {
            if (array_key_exists($key, $data)) {
                unset($data[$key]);
            }
        }

        return new self(JWK::create($data));
    }

    /**
     * @return array
     */
    public function toArray(): array
    {
        return $this->values;
    }

    /**
     * @param array $jwk
     */
    private function loadJWK(array $jwk)
    {
        if (!array_key_exists('kty', $jwk)) {
            throw new \InvalidArgumentException('The key parameter "kty" is missing.');
        }
        if ('RSA' !== $jwk['kty']) {
            throw new \InvalidArgumentException('The JWK is not a RSA key.');
        }

        $this->values = $jwk;
    }

    private function populateBigIntegers()
    {
        $this->modulus = $this->convertBase64StringToBigInteger($this->values['n']);
        $this->modulus_length = mb_strlen($this->getModulus()->toBytes(), '8bit');
        $this->public_exponent = $this->convertBase64StringToBigInteger($this->values['e']);

        if (!$this->isPublic()) {
            $this->private_exponent = $this->convertBase64StringToBigInteger($this->values['d']);

            if (array_key_exists('p', $this->values) && array_key_exists('q', $this->values)) {
                $this->primes = [
                    $this->convertBase64StringToBigInteger($this->values['p']),
                    $this->convertBase64StringToBigInteger($this->values['q']),
                ];
                if (array_key_exists('dp', $this->values) && array_key_exists('dq', $this->values) && array_key_exists('qi', $this->values)) {
                    $this->exponents = [
                        $this->convertBase64StringToBigInteger($this->values['dp']),
                        $this->convertBase64StringToBigInteger($this->values['dq']),
                    ];
                    $this->coefficient = $this->convertBase64StringToBigInteger($this->values['qi']);
                }
            }
        }
    }

    /**
     * @param string $value
     *
     * @return BigInteger
     */
    private function convertBase64StringToBigInteger(string $value): BigInteger
    {
        return BigInteger::createFromBinaryString(Base64Url::decode($value));
    }
}
