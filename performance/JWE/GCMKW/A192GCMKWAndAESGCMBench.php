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
 * @Groups({"JWE", "GCMKW", "A192GCMKW", "A128GCM", "A192GCM", "A256GCM"})
 */
final class A192GCMKWAndAESGCMBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                    'shared_protected_headers' => ['alg' => 'A192GCMKW', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192GCMKW', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'A192GCMKW', 'enc' => 'A256GCM'],
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
            ['input' => '{"ciphertext":"HkjX1OX7IhbkYVatuK71Uay5_Mk-NM7i1qj2dAX7ARdznuFtJtxsFU0GZ4Yfm4zHJQRNjbPQyoVqXmJAXaqIa6-sdKokLIyX6vOTM7KOj64A_BxH2nYV5H_0LKONd8tAhwGuMWXAccOM-tFOQd5TY2_THfGCCgM-iEM9hi3GJGxi5GeSNvzmLAU_f4WZ-sm_YJMj_RGC-Y3rE0r7zO4ssqN8kAdQhLk","iv":"ohd0x3pkbNq-Obrg","tag":"WAbMQa28YXhZFrHWzpIHag","aad":"QSxCLEMsRA","protected":"eyJpdiI6IlVmdUVHWDZkeTdiRjdqY28iLCJ0YWciOiJQZ3hlbXpab01hQUwzUzZlMnlTWW9RIiwiYWxnIjoiQTEyOEdDTUtXIiwiZW5jIjoiQTEyOEdDTSJ9","encrypted_key":"JazoFotGXi3JUoiD5PKAFA"}'],
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
