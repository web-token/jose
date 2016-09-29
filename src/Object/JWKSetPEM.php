<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

use Jose\KeyConverter\ECKey;
use Jose\KeyConverter\RSAKey;

/**
 * Class JWKSetPEM.
 */
trait JWKSetPEM
{
    /**
     * @return \Jose\Object\JWKInterface[]
     */
    abstract public function getKeys();

    /**
     * {@inheritdoc}
     */
    public function toPEM()
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
     * @param \Jose\Object\JWKInterface $key
     *
     * @return string
     */
    private function getPEM(JWKInterface $key)
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
