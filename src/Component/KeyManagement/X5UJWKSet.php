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
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;

/**
 * Class X5UJWKSet.
 */
final class X5UJWKSet extends DownloadedJWKSet
{
    /**
     * @return JWK[]
     */
    public function getKeys(): array
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
            $jwkset->addKey(JWK::create($jwk));
        }

        return $jwkset->getKeys();
    }
}
