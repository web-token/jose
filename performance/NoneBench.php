<?php

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
    public function dataSignatureAlgorithms(): array
    {
        return [
            [
                'algorithm' => 'none',
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
}
