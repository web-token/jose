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

use Jose\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Object\JWK;
use Jose\Object\JWKInterface;

function testKeyAgreementWithKeyWrappingEncryptionPerformance($message, KeyAgreementWrappingInterface $alg, JWKInterface $recipient_key)
{
    $header = [
        'alg' => $alg->getAlgorithmName(),
        'enc' => 'A128GCM',
        'exp' => time() + 3600,
        'iat' => time(),
        'nbf' => time(),
    ];
    $ahv = [];
    $cek = random_bytes(512);
    $nb = 100;

    $time_start = microtime(true);
    for ($i = 0; $i < $nb; ++$i) {
        $alg->wrapAgreementKey($recipient_key, $cek, 128, $header, $ahv);
    }
    $time_end = microtime(true);

    $time = ($time_end - $time_start) / $nb * 1000;
    printf('%s: %f milliseconds/wrapping of key agreement (%s)'.PHP_EOL, $alg->getAlgorithmName(), $time, $message);
}

function testKeyAgreementWithKeyWrappingDecryptionPerformance($message, KeyAgreementWrappingInterface $alg, JWKInterface $recipient_key, array $ahv)
{
    $header = [
        'alg' => $alg->getAlgorithmName(),
        'enc' => 'A128GCM',
        'exp' => time() + 3600,
        'iat' => time(),
        'nbf' => time(),
    ];
    $header = array_merge(
        $header,
        $ahv
    );
    $cek = random_bytes(512 / 8);

    $encrypted_cek = $alg->wrapAgreementKey($recipient_key, $cek, 128, $header, $header);
    $nb = 100;

    $time_start = microtime(true);
    for ($i = 0; $i < $nb; ++$i) {
        $alg->unwrapAgreementKey($recipient_key, $encrypted_cek, 128, $header);
    }
    $time_end = microtime(true);

    $time = ($time_end - $time_start) / $nb * 1000;
    printf('%s: %f milliseconds/unwrapping of key agreement (%s)'.PHP_EOL, $alg->getAlgorithmName(), $time, $message);
}

function dataPrivateKeyAgreementWithKeyWrappingPerformance()
{
    return [
        [
            'With P-256 curve',
            new ECDHESA128KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-256',
                    'x' => 'TZ7_dXun_REsafV7tFkNayKPDyL6EdxZ8hQmvDeKH0Y',
                    'y' => 'Z84xZQisnNDKfstsCuKidm-u7WYUYTHzo2UGtYgTcJ4',
                ],
            ],
        ],
        [
            'With P-384 curve',
            new ECDHESA128KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-384',
                'x' => 'IZ0VDYiwXq6qi19SdQe-rhX03T-hkGk7qZi7Y0sR-xXdngp2NCRkhE5eEqAUz2M0',
                'y' => 'SLv3QXabqdNMY5Ezolm7VqOWjG7kg5tXoGVWf6ooIuuRmrmnLG7_RzBGySzPXYn3',
                'd' => 'GBwKLCdSIOz9I6_1Imogi_NvqrbTDMONi-tjpxNnJ4FTG5RfLurTgTfVyl0-WWBu',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-384',
                    'x' => 'Wyidjnd4VBA3nih1RZCJJ1EkKgHSApODejS_JCReqg6K0RhxaIzr9jh_NRslfjnd',
                    'y' => 'kcGQFUrRDHqcj1dTwL_SOyaf6cnkp8dL5NX70WiV3Ti97bFLrCE1dfRGpnCPW4R6',
                ],
            ],
        ],
        [
            'With P-521 curve',
            new ECDHESA128KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
                'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-521',
                    'x' => 'Kv77LZEF4wD_L26EERJQ-iEZvEft-eWONIr2UjUNLoBZLhMvSV76lh3miGO0nzRGMi0vCx4OScDH3h-0I6wsF3Y',
                    'y' => 'V-h7CW1Rd_ylxI1qNNq4o0d_Hgu7x0l2WIeZDWXOW7kODJEfDZpxArNwp3x4NeIhfbYOEZRfu1Ho6dq5LKR80vM',
                ],
            ],
        ],
        [
            'With P-256 curve',
            new ECDHESA192KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-256',
                    'x' => 'TZ7_dXun_REsafV7tFkNayKPDyL6EdxZ8hQmvDeKH0Y',
                    'y' => 'Z84xZQisnNDKfstsCuKidm-u7WYUYTHzo2UGtYgTcJ4',
                ],
            ],
        ],
        [
            'With P-384 curve',
            new ECDHESA192KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-384',
                'x' => 'IZ0VDYiwXq6qi19SdQe-rhX03T-hkGk7qZi7Y0sR-xXdngp2NCRkhE5eEqAUz2M0',
                'y' => 'SLv3QXabqdNMY5Ezolm7VqOWjG7kg5tXoGVWf6ooIuuRmrmnLG7_RzBGySzPXYn3',
                'd' => 'GBwKLCdSIOz9I6_1Imogi_NvqrbTDMONi-tjpxNnJ4FTG5RfLurTgTfVyl0-WWBu',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-384',
                    'x' => 'Wyidjnd4VBA3nih1RZCJJ1EkKgHSApODejS_JCReqg6K0RhxaIzr9jh_NRslfjnd',
                    'y' => 'kcGQFUrRDHqcj1dTwL_SOyaf6cnkp8dL5NX70WiV3Ti97bFLrCE1dfRGpnCPW4R6',
                ],
            ],
        ],
        [
            'With P-521 curve',
            new ECDHESA192KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
                'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-521',
                    'x' => 'Kv77LZEF4wD_L26EERJQ-iEZvEft-eWONIr2UjUNLoBZLhMvSV76lh3miGO0nzRGMi0vCx4OScDH3h-0I6wsF3Y',
                    'y' => 'V-h7CW1Rd_ylxI1qNNq4o0d_Hgu7x0l2WIeZDWXOW7kODJEfDZpxArNwp3x4NeIhfbYOEZRfu1Ho6dq5LKR80vM',
                ],
            ],
        ],
        [
            'With P-256 curve',
            new ECDHESA256KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-256',
                    'x' => 'TZ7_dXun_REsafV7tFkNayKPDyL6EdxZ8hQmvDeKH0Y',
                    'y' => 'Z84xZQisnNDKfstsCuKidm-u7WYUYTHzo2UGtYgTcJ4',
                ],
            ],
        ],
        [
            'With P-384 curve',
            new ECDHESA256KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-384',
                'x' => 'IZ0VDYiwXq6qi19SdQe-rhX03T-hkGk7qZi7Y0sR-xXdngp2NCRkhE5eEqAUz2M0',
                'y' => 'SLv3QXabqdNMY5Ezolm7VqOWjG7kg5tXoGVWf6ooIuuRmrmnLG7_RzBGySzPXYn3',
                'd' => 'GBwKLCdSIOz9I6_1Imogi_NvqrbTDMONi-tjpxNnJ4FTG5RfLurTgTfVyl0-WWBu',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-384',
                    'x' => 'Wyidjnd4VBA3nih1RZCJJ1EkKgHSApODejS_JCReqg6K0RhxaIzr9jh_NRslfjnd',
                    'y' => 'kcGQFUrRDHqcj1dTwL_SOyaf6cnkp8dL5NX70WiV3Ti97bFLrCE1dfRGpnCPW4R6',
                ],
            ],
        ],
        [
            'With P-521 curve',
            new ECDHESA256KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
                'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            ]),
            [
                'epk' => [
                    'kty' => 'EC',
                    'crv' => 'P-521',
                    'x' => 'Kv77LZEF4wD_L26EERJQ-iEZvEft-eWONIr2UjUNLoBZLhMvSV76lh3miGO0nzRGMi0vCx4OScDH3h-0I6wsF3Y',
                    'y' => 'V-h7CW1Rd_ylxI1qNNq4o0d_Hgu7x0l2WIeZDWXOW7kODJEfDZpxArNwp3x4NeIhfbYOEZRfu1Ho6dq5LKR80vM',
                ],
            ],
        ],
    ];
}

function dataPublicKeyAgreementWithKeyWrappingPerformance()
{
    return [
        [
            'With P-256 curve',
            new ECDHESA128KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            ]),
        ],
        [
            'With P-384 curve',
            new ECDHESA128KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-384',
                'x' => 'IZ0VDYiwXq6qi19SdQe-rhX03T-hkGk7qZi7Y0sR-xXdngp2NCRkhE5eEqAUz2M0',
                'y' => 'SLv3QXabqdNMY5Ezolm7VqOWjG7kg5tXoGVWf6ooIuuRmrmnLG7_RzBGySzPXYn3',
            ]),
        ],
        [
            'With P-521 curve',
            new ECDHESA128KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
            ]),
        ],
        [
            'With P-256 curve',
            new ECDHESA192KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            ]),
        ],
        [
            'With P-384 curve',
            new ECDHESA192KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-384',
                'x' => 'IZ0VDYiwXq6qi19SdQe-rhX03T-hkGk7qZi7Y0sR-xXdngp2NCRkhE5eEqAUz2M0',
                'y' => 'SLv3QXabqdNMY5Ezolm7VqOWjG7kg5tXoGVWf6ooIuuRmrmnLG7_RzBGySzPXYn3',
            ]),
        ],
        [
            'With P-521 curve',
            new ECDHESA192KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
            ]),
        ],
        [
            'With P-256 curve',
            new ECDHESA256KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            ]),
        ],
        [
            'With P-384 curve',
            new ECDHESA256KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-384',
                'x' => 'IZ0VDYiwXq6qi19SdQe-rhX03T-hkGk7qZi7Y0sR-xXdngp2NCRkhE5eEqAUz2M0',
                'y' => 'SLv3QXabqdNMY5Ezolm7VqOWjG7kg5tXoGVWf6ooIuuRmrmnLG7_RzBGySzPXYn3',
            ]),
        ],
        [
            'With P-521 curve',
            new ECDHESA256KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
            ]),
        ],
    ];
}

print_r('#####################################################'.PHP_EOL);
print_r('# KEY AGREEMENT WITH KEY WRAPPING PERFORMANCE TESTS #'.PHP_EOL);
print_r('#####################################################'.PHP_EOL);

foreach (dataPublicKeyAgreementWithKeyWrappingPerformance() as $environment) {
    testKeyAgreementWithKeyWrappingEncryptionPerformance($environment[0], $environment[1], $environment[2]);
}
foreach (dataPrivateKeyAgreementWithKeyWrappingPerformance() as $environment) {
    testKeyAgreementWithKeyWrappingDecryptionPerformance($environment[0], $environment[1], $environment[2], $environment[3]);
}

print_r('#####################################################'.PHP_EOL);
