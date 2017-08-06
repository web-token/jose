<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWS\Creation;

use Jose\Component\Core\JWK;

/**
 * @Groups({"JWS", "hmac"})
 */
final class HS512Bench extends SignatureBench
{
    /**
     * @return array
     */
    public function dataSignature(): array
    {
        return [
            [
                'algorithm' => 'HS512',
            ],
        ];
    }

    /**
     * @return array
     */
    public function dataVerification(): array
    {
        return [
            [
                'input' => 'eyJhbGciOiJIUzUxMiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.1iIN1THXoEvVr6OiIZ2jTqAsmTF0UAut_cZ6GCy31zHc66MZmfo_0uAYEoVvz1IpfC--ZPSocgY8ImtCNfDVRQ',
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getPrivateKey(): JWK
    {
        return JWK::create([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getPublicKey(): JWK
    {
        return $this->getPrivateKey();
    }
}
