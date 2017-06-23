<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement;

use Jose\Component\Core\BaseJWKSet;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSetInterface;
use Jose\Component\Core\JWKSetPEM;

/**
 * Class PublicJWKSet.
 */
final class PublicJWKSet implements JWKSetInterface
{
    use BaseJWKSet;
    use JWKSetPEM;

    /**
     * @var \Jose\Component\Core\JWKSetInterface
     */
    private $jwkset;

    /**
     * PublicJWKSet constructor.
     *
     * @param \Jose\Component\Core\JWKSetInterface $jwkset
     */
    public function __construct(JWKSetInterface $jwkset)
    {
        $this->jwkset = $jwkset;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeys(): array
    {
        $keys = [];

        foreach ($this->jwkset->getKeys() as $key) {
            if (in_array($key->get('kty'), ['none', 'oct'])) {
                continue;
            }
            $keys[] = $key->toPublic();
        }

        return $keys;
    }

    /**
     * {@inheritdoc}
     */
    public function addKey(JWK $key)
    {
        $this->jwkset->addKey($key);
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey(int $index)
    {
        //Not available
    }
}
