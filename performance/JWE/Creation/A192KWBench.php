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
 * @Groups({"JWE", "A192KW"})
 */
final class A192KWBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ],
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ],
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A256CBC-HS512'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ],
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ],
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ],
            ],
            [
                'data' => [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A256GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
                ],
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
            'alg' => 'A192KW',
            'k' => 'KuFiR-n2ngkDNZfBXWS6cCGXrYonVUiH',
        ]);
    }
}
