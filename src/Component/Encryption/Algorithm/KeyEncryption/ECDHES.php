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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Util\Ecc\EcDH;
use Jose\Component\Encryption\Util\Ecc\PrivateKey;
use Jose\Component\Encryption\Util\Ecc\NistCurve;
use Jose\Component\Encryption\Util\Ecc\Curve;
use Jose\Component\Encryption\Util\ConcatKDF;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * Class ECDHES.
 */
final class ECDHES implements KeyAgreementInterface
{
    /**
     * {@inheritdoc}
     */
    public function getAgreementKey(int $encryption_key_length, string $algorithm, JWK $recipient_key, array $complete_header = [], array &$additional_header_values = []): string
    {
        if ($recipient_key->has('d')) {
            $this->checkKey($recipient_key, true);
            $private_key = $recipient_key;
            $public_key = $this->getPublicKey($complete_header);
        } else {
            $this->checkKey($recipient_key, false);
            $public_key = $recipient_key;
            switch ($public_key->get('crv')) {
                case 'P-256':
                case 'P-384':
                case 'P-521':
                    $private_key = JWKFactory::createECKey($public_key->get('crv'));

                    break;
                case 'X25519':
                    $private_key = JWKFactory::createOKPKey('X25519');

                    break;
                default:
                    throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported', $public_key->get('crv')));
            }
            $epk = $private_key->toPublic()->all();
            $additional_header_values = array_merge($additional_header_values, [
                'epk' => $epk,
            ]);
        }
        if ($private_key->get('crv') !== $public_key->get('crv')) {
            throw new \InvalidArgumentException('Curves are different');
        }

        $agreed_key = $this->calculateAgreementKey($private_key, $public_key);

        $apu = array_key_exists('apu', $complete_header) ? $complete_header['apu'] : '';
        $apv = array_key_exists('apv', $complete_header) ? $complete_header['apv'] : '';

        return ConcatKDF::generate($agreed_key, $algorithm, $encryption_key_length, $apu, $apv);
    }

    /**
     * @param JWK $private_key
     * @param JWK $public_key
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    public function calculateAgreementKey(JWK $private_key, JWK $public_key): string
    {
        switch ($public_key->get('crv')) {
            case 'P-256':
            case 'P-384':
            case 'P-521':
                $curve = $this->getCurve($private_key);

                $rec_x = $this->convertBase64ToGmp($public_key->get('x'));
                $rec_y = $this->convertBase64ToGmp($public_key->get('y'));
                $sen_d = $this->convertBase64ToGmp($private_key->get('d'));

                $priv_key = PrivateKey::create($sen_d);
                $pub_key = $curve->getPublicKeyFrom($rec_x, $rec_y);

                return $this->convertDecToBin(EcDH::computeSharedKey($curve, $pub_key, $priv_key));
            case 'X25519':
                $sKey = Base64Url::decode($private_key->get('d'));
                $recipientPublickey = Base64Url::decode($public_key->get('x'));

                return sodium_crypto_scalarmult($sKey, $recipientPublickey);
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported', $public_key->get('crv')));
        }
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'ECDH-ES';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_AGREEMENT;
    }

    /**
     * @param array $complete_header
     *
     * @return JWK
     */
    private function getPublicKey(array $complete_header)
    {
        if (!array_key_exists('epk', $complete_header)) {
            throw new \InvalidArgumentException('The header parameter "epk" is missing');
        }
        if (!is_array($complete_header['epk'])) {
            throw new \InvalidArgumentException('The header parameter "epk" is not an array of parameter');
        }

        $public_key = JWK::create($complete_header['epk']);
        $this->checkKey($public_key, false);

        return $public_key;
    }

    /**
     * @param JWK  $key
     * @param bool $is_private
     */
    private function checkKey(JWK $key, $is_private)
    {
        foreach (['x', 'crv'] as $k) {
            if (!$key->has($k)) {
                throw new \InvalidArgumentException(sprintf('The key parameter "%s" is missing.', $k));
            }
        }

        switch ($key->get('crv')) {
            case 'P-256':
            case 'P-384':
            case 'P-521':
                if ('EC' !== $key->get('kty')) {
                    throw new \InvalidArgumentException('Wrong key type.');
                }
                if (!$key->has('y')) {
                    throw new \InvalidArgumentException('The key parameter "y" is missing.');
                }

                break;
            case 'X25519':
                if ('OKP' !== $key->get('kty')) {
                    throw new \InvalidArgumentException('Wrong key type.');
                }

                break;
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported', $key->get('crv')));
        }
        if (true === $is_private) {
            if (!$key->has('d')) {
                throw new \InvalidArgumentException('The key parameter "d" is missing.');
            }
        }
    }

    /**
     * @param JWK $key
     *
     * @throws \InvalidArgumentException
     *
     * @return Curve
     */
    private function getCurve(JWK $key): Curve
    {
        $crv = $key->get('crv');

        switch ($crv) {
            case 'P-256':
                return NistCurve::curve256();
            case 'P-384':
                return NistCurve::curve384();
            case 'P-521':
                return NistCurve::curve521();
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported', $crv));
        }
    }

    /**
     * @param string $value
     *
     * @return \GMP
     */
    private function convertBase64ToGmp(string $value): \GMP
    {
        $value = unpack('H*', Base64Url::decode($value));

        return gmp_init($value[1], 16);
    }

    /**
     * @param \GMP $dec
     *
     * @return string
     */
    private function convertDecToBin(\GMP $dec): string
    {
        if (gmp_cmp($dec, 0) < 0) {
            throw new \InvalidArgumentException('Unable to convert negative integer to string');
        }

        $hex = gmp_strval($dec, 16);

        if (mb_strlen($hex, '8bit') % 2 !== 0) {
            $hex = '0'.$hex;
        }

        return hex2bin($hex);
    }
}
