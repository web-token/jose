<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

use Jose\Component\KeyManagement\KeyConverter\ECKey;
use Jose\Component\KeyManagement\KeyConverter\RSAKey;

/**
 * Class JWKSetPEM.
 */
trait JWKSetPEM
{
    /**
     * @return JWK[]
     */
    abstract public function getKeys(): array;

    /**
     * {@inheritdoc}
     */
    public function toPEM(): array
    {
        $keys = $this->getKeys();
        $result = [];

        foreach ($keys as $key) {
            if (!in_array($key->get('kty'), ['RSA', 'EC'])) {
                continue;
            }

            $pem = $this->getPEM($key);
            if ($key->has('kid')) {
                $result[$key->get('kid')] = $pem;
            } else {
                $result[] = $pem;
            }
        }

        return $result;
    }

    /**
     * @param JWK $key
     *
     * @return string
     */
    private function getPEM(JWK $key): string
    {
        switch ($key->get('kty')) {
            case 'RSA':
                return (new RSAKey($key))->toPEM();
            case 'EC':
                return (new ECKey($key))->toPEM();
            default:
                throw new \InvalidArgumentException('Unsupported key type.');
        }
    }
}
