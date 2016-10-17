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
use Jose\KeyConverter\KeyConverter;

/**
 * Class JKUJWKSet.
 */
final class X5UJWKSet extends DownloadedJWKSet
{
    /**
     * @return \Jose\Object\JWKInterface[]
     */
    public function getKeys()
    {
        $content = json_decode($this->getContent(), true);
        Assertion::isArray($content, 'Invalid content.');
        $jwkset = new JWKSet();
        foreach ($content as $kid => $cert) {
            $jwk = KeyConverter::loadKeyFromCertificate($cert);
            Assertion::notEmpty($jwk, 'Invalid content.');
            if (is_string($kid)) {
                $jwk['kid'] = $kid;
            }
            $jwkset->addKey(new JWK($jwk));
        }

        return $jwkset->getKeys();
    }
}
