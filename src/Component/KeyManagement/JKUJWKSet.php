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

use Assert\Assertion;
use Jose\Component\Core\JWKSet;

/**
 * Class JKUJWKSet.
 */
final class JKUJWKSet extends DownloadedJWKSet
{
    /**
     * {@inheritdoc}
     */
    public function getKeys(): array
    {
        $content = json_decode($this->getContent(), true);
        Assertion::isArray($content, 'Invalid content.');
        Assertion::keyExists($content, 'keys', 'Invalid content.');

        return (new JWKSet($content))->getKeys();
    }
}
