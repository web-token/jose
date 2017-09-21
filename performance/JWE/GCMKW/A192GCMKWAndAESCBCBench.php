<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWE\GCMKW;

use Jose\Performance\JWE\EncryptionBench;

/**
 * @Revs(4096)
 * @Groups({"JWE", "GCMKW", "A192GCMKW", "A128CBCHS256", "A192CBCHS384", "A256CBCHS512"})
 */
final class A192GCMKWAndAESCBCBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                    'shared_protected_headers' => ['alg' => 'A192GCMKW', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192GCMKW', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192GCMKW', 'enc' => 'A256CBC-HS512'],
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
            ['input' => '{"ciphertext":"K0S43PsiO4oPGguOY3hkEjWV5VMVf_b5uwrIZMV6FfWEpjE549tkRg95teAXCiik5vEp18S1TiBCnzwFt-xt3HpeZrZ6h-3skB8vPe912vY8P18ZMKYL-vKjl74gTN5N3Bw4Mh5BYIFSWOFb1RqQu5Ssc7psTEWHvmBJkyapoS5B2HA0ATD2bvJJ3O1Z0OiD658zb2DC8gIf6fXrY-JfHB7rGgZ2Y6A6m7QrDr48i4Q","iv":"FFx1sqqwbkMtqVP19z2vew","tag":"cwIDKbnXh9CAwYN9Vvnpdw","aad":"QSxCLEMsRA","protected":"eyJpdiI6IjY4dkdib2tBbVhoeFRKT0EiLCJ0YWciOiJ1QjJSYi1vWGZHSDZvNzhCbDhRdmVBIiwiYWxnIjoiQTEyOEdDTUtXIiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9","encrypted_key":"i0tLidRGQqTsqMd591N0mh8AyjBc9eMp4AjIpqxbHwQ"}'],
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
                    'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
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
                    'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
                ],
            ],
        ];
    }
}
