<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Class JWKSet.
 */
final class JWKSet extends BaseJWKSet implements JWKSetInterface
{
    use JWKSetPEM;

    /**
     * @var array
     */
    protected $keys = [];

    public function __construct(array $keys = [])
    {
        if (array_key_exists('keys', $keys)) {
            foreach ($keys['keys'] as $value) {
                $this->addKey(new JWK($value));
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKeys()
    {
        return $this->keys;
    }

    /**
     * {@inheritdoc}
     */
    public function addKey(JWKInterface $key)
    {
        $this->keys[] = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function prependKey(JWKInterface $key)
    {
        array_unshift($this->keys, $key);
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($key)
    {
        if (array_key_exists($key, $this->keys)) {
            unset($this->keys[$key]);
        }
    }
}
