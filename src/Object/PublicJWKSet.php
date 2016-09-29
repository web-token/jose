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

/**
 * Class PublicJWKSet.
 */
final class PublicJWKSet implements JWKSetInterface
{
    use BaseJWKSet;
    use JWKSetPEM;

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    private $jwkset;

    /**
     * PublicJWKSet constructor.
     *
     * @param \Jose\Object\JWKSetInterface $jwkset
     */
    public function __construct(JWKSetInterface $jwkset)
    {
        $this->jwkset = $jwkset;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeys()
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
    public function addKey(JWKInterface $key)
    {
        $this->jwkset->addKey($key);
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($index)
    {
        //Not available
    }
}
