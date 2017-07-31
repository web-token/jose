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
 * @Groups({"ECDSA"})
 */
final class ES512Bench extends SignatureBench
{
    /**
     * @return array
     */
    public function dataSignature(): array
    {
        return [
            [
                'algorithm' => 'ES512',
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
                'input' => 'eyJhbGciOiJFUzUxMiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.AHWHIEWLWQl8n07gsrSx-UvwtUX1Clp-8QCJX20ifv3glXIJMRj9kiB8MlpKA_cpTaEROgf4apb5BYNqi3V4s7_CANg0hFc6_gJ-ECAjanlIVrXhFdJhDyIMhEkBkA3cq6HsWulJeZinP5CU-4_oNup--ir_PfQcui1jpboNwER6_XRG',
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getPrivateKey(): JWK
    {
        return JWK::create([
            'kty' => 'EC',
            'kid' => 'bilbo.baggins@hobbiton.example',
            'use' => 'sig',
            'crv' => 'P-521',
            'x' => 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt',
            'y' => 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1',
            'd' => 'AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt',
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getPublicKey(): JWK
    {
        return $this->getPrivateKey()->toPublic();
    }
}
