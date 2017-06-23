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

/**
 * Class JWKSet.
 */
final class JWKSet implements JWKSetInterface
{
    use BaseJWKSet;
    use JWKSetPEM;

    /**
     * @var array
     */
    private $keys = [];

    public function __construct(array $keys = [])
    {
        if (array_key_exists('keys', $keys)) {
            foreach ($keys['keys'] as $value) {
                $this->addKey(JWK::create($value));
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKeys(): array
    {
        return $this->keys;
    }

    /**
     * {@inheritdoc}
     */
    public function addKey(JWK $key)
    {
        $this->keys[] = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey(int $key)
    {
        if (isset($this->keys[$key])) {
            unset($this->keys[$key]);
        }
    }
}
