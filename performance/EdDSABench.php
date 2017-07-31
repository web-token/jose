<?php

namespace Jose\Performance;

use Jose\Component\Core\JWK;

/**
 * @Groups({"EdDSA"})
 */
final class EdDSABench extends SignatureBench
{
    /**
     * @return array
     */
    public function dataSignatureAlgorithms(): array
    {
        return [
            [
                'algorithm' => 'EdDSA',
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getPrivateKey(): JWK
    {
        return JWK::create([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);
    }
}
