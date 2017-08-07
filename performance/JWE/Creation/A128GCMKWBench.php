<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWE\Creation;

use Jose\Component\Core\JWK;
use Jose\Performance\JWE\EncryptionBench;

/**
 * @Groups({"JWE", "A128GCMKW"})
 */
final class A128GCMKWBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A128GCMKW', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ]
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A128GCMKW', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ]
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A128GCMKW', 'enc' => 'A256CBC-HS512'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ]
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A128GCMKW', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ]
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A128GCMKW', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ]
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A128GCMKW', 'enc' => 'A256GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ]
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getRecipientPublicKey(): JWK
    {
        return $this->getRecipientPrivateKey()->toPublic();
    }

    /**
     * {@inheritdoc}
     */
    protected function getAAD(): ?string
    {
        return 'A,B,C,D';
    }

    /**
     * {@inheritdoc}
     */
    protected function getRecipientPrivateKey(): JWK
    {
        return JWK::create([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128GCMKW',
            'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);
    }
}
