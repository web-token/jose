<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance;

use Jose\Component\Core\JWK;

/**
 * @Groups({"None"})
 */
final class NoneBench extends SignatureBench
{
    /**
     * @return array
     */
    public function dataSignature(): array
    {
        return [
            [
                'algorithm' => 'none',
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
                'input' => 'eyJhbGciOiJub25lIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.',
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getPrivateKey(): JWK
    {
        return JWK::create([
            'kty' => 'none',
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
