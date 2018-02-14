<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

include_once __DIR__.'/../../vendor/autoload.php';

use Jose\Algorithm\KeyEncryption\ECDHES;
use Jose\Algorithm\KeyEncryption\KeyAgreementInterface;
use Jose\Factory\JWKFactory;
use Jose\Object\JWK;
use Jose\Object\JWKInterface;

function testKeyAgreementPerformance($message, KeyAgreementInterface $alg, JWKInterface $recipient_key)
{
    $header = [
        'alg' => $alg->getAlgorithmName(),
        'enc' => 'A256CBC-HS512',
        'exp' => time() + 3600,
        'iat' => time(),
        'nbf' => time(),
    ];
    $ahv = [];
    $nb = 100;

    $time_start = microtime(true);
    for ($i = 0; $i < $nb; ++$i) {
        $alg->getAgreementKey(512 / 8, 'A256GCM', $recipient_key, $header, $ahv);
    }

    $time_end = microtime(true);
    $time = ($time_end - $time_start) / $nb * 1000;
    printf('%s: %f milliseconds/key agreement (%s)'.PHP_EOL, $alg->getAlgorithmName(), $time, $message);
}

function dataKeyAgreementPerformance()
{
    return [
        [
            'With X25519 curve',
            new ECDHES(),
            JWKFactory::createOKPKey([
                'crv' => 'X25519',
                'kid' => 'KEY1',
                'alg' => 'ECDH-ES',
                'use' => 'enc',
            ])->toPublic(),
        ],
        [
            'With P-256 curve',
            new ECDHES(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            ]),
        ],
        [
            'With P-384 curve',
            new ECDHES(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-384',
                'x' => 'IZ0VDYiwXq6qi19SdQe-rhX03T-hkGk7qZi7Y0sR-xXdngp2NCRkhE5eEqAUz2M0',
                'y' => 'SLv3QXabqdNMY5Ezolm7VqOWjG7kg5tXoGVWf6ooIuuRmrmnLG7_RzBGySzPXYn3',
            ]),
        ],
        [
            'With P-521 curve',
            new ECDHES(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y' => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            ]),
        ],
    ];
}

$environments = dataKeyAgreementPerformance();

print_r('###################################'.PHP_EOL);
print_r('# KEY AGREEMENT PERFORMANCE TESTS #'.PHP_EOL);
print_r('###################################'.PHP_EOL);

foreach ($environments as $environment) {
    testKeyAgreementPerformance($environment[0], $environment[1], $environment[2]);
}

print_r('###################################'.PHP_EOL);
