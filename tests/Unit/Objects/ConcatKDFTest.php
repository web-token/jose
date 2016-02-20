<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Base64Url\Base64Url;
use Jose\Algorithm\KeyEncryption\ECDHES;
use Jose\Object\JWK;
use Jose\Util\ConcatKDF;

/**
 * Class ConcatKDFTest.
 *
 * @group ConcatKDF
 * @group Unit
 */
class ConcatKDFTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7518#appendix-C
     */
    public function testConcatKDF()
    {
        $alice_key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);
        $bob_key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $expected_ephemeral_key = ['epk' => [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        ]];

        $complete_header = [
            'alg' => 'ECDH-ES',
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];

        $additional_header = [];
        $ecdh_es = new ECDHES();
        $agreement_key = $ecdh_es->getAgreementKey(
            128,
            $alice_key,
            $bob_key,
            $complete_header,
            $additional_header
        );

        $Z = [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196];

        $expected_kdf = 'VqqN6vgjbSBcIijNcacQGg';

        $kdf = ConcatKDF::generate(
            $this->convertArrayToBinString($Z),
            'A128GCM',
            128,
            'QWxpY2U',
            'Qm9i'
        );

        $this->assertEquals($expected_kdf, Base64Url::encode($agreement_key));
        $this->assertEquals($expected_kdf, Base64Url::encode($kdf));
        $this->assertEquals($expected_ephemeral_key, $additional_header);
    }

    /**
     * @param array $data
     *
     * @return string
     */
    private function convertArrayToBinString(array $data)
    {
        foreach ($data as $key => $value) {
            $data[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }

        return hex2bin(implode('', $data));
    }
}
