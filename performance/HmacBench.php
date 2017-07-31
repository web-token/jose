<?php

namespace Jose\Performance;

use Jose\Component\Core\JWK;

/**
 * @Groups({"hmac"})
 */
final class HmacBench extends SignatureBench
{
    /**
     * @return array
     */
    public function dataSignatureAlgorithms(): array
    {
        return [
            [
                'algorithm' => 'HS256',
            ],
            [
                'algorithm' => 'HS384',
            ],
            [
                'algorithm' => 'HS512',
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


}
