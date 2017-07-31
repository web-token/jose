<?php

namespace Jose\Performance;

use Jose\Component\Core\JWK;

/**
 * @Groups({"ECDSA"})
 */
final class EC256Bench extends SignatureBench
{
    /**
     * @return array
     */
    public function dataSignatureAlgorithms(): array
    {
        return [
            [
                'algorithm' => 'ES256',
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
            'kid' => 'meriadoc.brandybuck@buckland.example',
            'use' => 'sig',
            'crv' => 'P-256',
            'x' => 'Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0',
            'y' => 'HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw',
            'd' => 'r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8',
        ]);
    }
}
