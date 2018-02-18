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

use Assert\Assertion;

/**
 * Class JWKSets.
 */
final class JWKSets extends BaseJWKSet implements JWKSetsInterface
{
    use JWKSetPEM;

    /**
     * @var \Jose\Object\JWKSetInterface[]
     */
    private $jwksets = [];

    /**
     * JWKSets constructor.
     *
     * @param \Jose\Object\JWKSetInterface[] $jwksets
     */
    public function __construct(array $jwksets = [])
    {
        Assertion::allIsInstanceOf($jwksets, JWKSetInterface::class);

        $this->jwksets = $jwksets;
    }

    /**
     * {@inheritdoc}
     */
    public function addKeySet(JWKSetInterface $jwkset)
    {
        $this->jwksets[] = $jwkset;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeys()
    {
        $keys = [];

        foreach ($this->jwksets as $jwkset) {
            $keys = array_merge(
                $keys,
                $jwkset->getKeys()
            );
        }

        return $keys;
    }

    /**
     * {@inheritdoc}
     */
    public function addKey(JWKInterface $key)
    {
        //Not available
    }

    /**
     * {@inheritdoc}
     */
    public function prependKey(JWKInterface $key)
    {
        //Not available
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($index)
    {
        //Not available
    }
}
