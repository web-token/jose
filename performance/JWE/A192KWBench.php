<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWE;

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
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A256CBC-HS512'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192KW', 'enc' => 'A256GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
        ];
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
    public function dataInputs(): array
    {
        return [
            ['input' => '{"ciphertext":"0TnU-JWyzWNe_u5lzwI1PmI1P1A_9rDJSy-1-aVqgu5I4h9L7nGaqMpfJ2VRnEky8BG8khRJ9ytdgPEr5xlMw5Me1OHhcALIvjdtUO_yQvj4ndn6VWSAuyfC4WzyBdRhwufh4RYPhXhh4mXYmvCzfQYD9KCiCB2PyA-WFg6vOgp5_kBbm1auxsarPkqFwfqNAMBavnKnuliaZviJE0708kWMJE8PuBA","iv":"4K9DpGqWCJ6MNNRn","tag":"s5EsBBRfzlFMnLuUU8TMPg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"GU6WSPFGiMK2hMXOQv6jbSZlTQ0p1hQL3KOIPTr9BYw6PtoTbrdUrg"}'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => ['keys' => [[
                    'kty' => 'oct',
                    'k' => 'KuFiR-n2ngkDNZfBXWS6cCGXrYonVUiH',
                ]]],
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function dataRecipientPublicKeys(): array
    {
        return [
            [
                'recipient_key' => [
                    'kty' => 'oct',
                    'k' => 'KuFiR-n2ngkDNZfBXWS6cCGXrYonVUiH',
                ],
            ],
        ];
    }
}
