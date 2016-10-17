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

use Assert\Assertion;

/**
 * Class JKUJWKSet.
 */
final class JKUJWKSet extends DownloadedJWKSet
{
    /**
     * @return \Jose\Object\JWKInterface[]
     */
    public function getKeys()
    {
        $content = json_decode($this->getContent(), true);
        Assertion::isArray($content, 'Invalid content.');
        Assertion::keyExists($content, 'keys', 'Invalid content.');

        return (new JWKSet($content))->getKeys();
    }
}
