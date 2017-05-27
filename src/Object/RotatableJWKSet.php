<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Class RotatableJWKSet.
 */
final class RotatableJWKSet extends StorableJWKSet implements RotatableInterface, JWKSetInterface
{
    /**
     * {@inheritdoc}
     */
    public function rotate()
    {
        $this->loadObjectIfNeeded();
        $jwkset = $this->getObject();

        $keys = $jwkset->getKeys();
        unset($keys[count($keys) - 1]);
        $jwkset = new JWKSet();
        $jwkset->addKey($this->createJWK());
        foreach ($keys as $key) {
            $jwkset->addKey($key);
        }
        $this->setObject($jwkset);
        $this->saveObject($jwkset);
    }
}
