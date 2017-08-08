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
 * @Groups({"JWE", "PBES2HS256A128KW"})
 */
final class PBES2HS512A256KWBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                    'shared_protected_headers' => ['alg' => 'PBES2-HS512+A256KW', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'PBES2-HS512+A256KW', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'PBES2-HS512+A256KW', 'enc' => 'A256CBC-HS512'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'PBES2-HS512+A256KW', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'PBES2-HS512+A256KW', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'PBES2-HS512+A256KW', 'enc' => 'A256GCM'],
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
            [
                'input' => '{"ciphertext":"GwXyadX97ssIytJawPP4112MOuBSxRXpiH-Ur7wtsThL3f0QZ2mjYoLYbFCql2A4j4avuSHjZH0LrIYX5Tt6zdLPVCZtUj_R_5mlFIfQW5cSVHTKBFLNA_xsn03eU3ANIq2CUdq6Sypk3f9UqJXgxN8XTR4wsFSSM11MEfWU3uSsgR1GTUOw04BPCMONi-gi-Fx1CTlTOGOQngDCNrLEnRR5KQpZ36c","iv":"byyjW61x3VFA2Bbi","tag":"cFjxlfvdpJqDepENC0bGNA","aad":"QSxCLEMsRA","protected":"eyJwMnMiOiI1QzI2YUpCZktVR2ZMaElkY0E0OVVONnNEX05aQnpjNC1xSDc0d1BNc0xhaTZUYnU0RXJRT2JRRFZxWFdtU2JvVzd4aGxFNUJUMkZ3VHFvY21NRHoydyIsInAyYyI6NDA5NiwiYWxnIjoiUEJFUzItSFM1MTIrQTI1NktXIiwiZW5jIjoiQTI1NkdDTSJ9","encrypted_key":"mxZpygw38j8rYa_qZP3Vb2RZf6n3s--7H1oxECBZGoaC_I0-qERoww"}',
            ],
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
                    'k' => 'OgUyABAPIkI-zFg3doqsv_GH-4GTGOu3HGnuG9wdxCo',
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
                    'k' => 'OgUyABAPIkI-zFg3doqsv_GH-4GTGOu3HGnuG9wdxCo',
                ],
            ],
        ];
    }
}
