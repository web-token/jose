<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Factory\JWKFactory;
use Jose\Object\JWK;
use Jose\Object\JWKInterface;
use Jose\Util\ConcatKDF;
use Mdanter\Ecc\Crypto\EcDH\EcDH;
use Mdanter\Ecc\EccFactory;

/**
 * Class ECDHES.
 */
final class ECDHES implements KeyAgreementInterface
{
    /**
     * {@inheritdoc}
     */
    public function getAgreementKey($encryption_key_length, $algorithm, JWKInterface $recipient_key, array $complete_header = [], array &$additional_header_values = [])
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
                    $private_key = JWKFactory::createECKey(['crv' => $public_key->get('crv')]);

                    break;
                case 'X25519':
                    $private_key = JWKFactory::createOKPKey(['crv' => 'X25519']);

                    break;
                default:
                    throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported', $public_key->get('crv')));
            }
            $epk = $private_key->toPublic()->getAll();
            $additional_header_values = array_merge($additional_header_values, [
                'epk' => $epk,
            ]);
        }
        Assertion::eq($private_key->get('crv'), $public_key->get('crv'), 'Curves are different');

        $agreed_key = $this->calculateAgreementKey($private_key, $public_key);

        $apu = array_key_exists('apu', $complete_header) ? $complete_header['apu'] : '';
        $apv = array_key_exists('apv', $complete_header) ? $complete_header['apv'] : '';

        return ConcatKDF::generate($agreed_key, $algorithm, $encryption_key_length, $apu, $apv);
    }

    /**
     * @param \Jose\Object\JWKInterface $private_key
     * @param \Jose\Object\JWKInterface $public_key
     *
     * @throws \InvalidArgumentException
     *
     * @return int|string|void
     */
    public function calculateAgreementKey(JWKInterface $private_key, JWKInterface $public_key)
    {
        switch ($public_key->get('crv')) {
            case 'P-256':
            case 'P-384':
            case 'P-521':
                $p = $this->getGenerator($private_key);

                $rec_x = $this->convertBase64ToGmp($public_key->get('x'));
                $rec_y = $this->convertBase64ToGmp($public_key->get('y'));
                $sen_d = $this->convertBase64ToGmp($private_key->get('d'));

                $priv_key = $p->getPrivateKeyFrom($sen_d);
                $pub_key = $p->getPublicKeyFrom($rec_x, $rec_y);

                $ecdh = new EcDH(EccFactory::getAdapter());
                $ecdh->setSenderKey($priv_key);
                $ecdh->setRecipientKey($pub_key);

                return $this->convertDecToBin($ecdh->calculateSharedKey());
            case 'X25519':
                return curve25519_shared(
                    Base64Url::decode($private_key->get('d')),
                    Base64Url::decode($public_key->get('x'))
                );
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported', $public_key->get('crv')));
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'ECDH-ES';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode()
    {
        return self::MODE_AGREEMENT;
    }

    /**
     * @param array $complete_header
     *
     * @return \Jose\Object\JWKInterface
     */
    private function getPublicKey(array $complete_header)
    {
        Assertion::keyExists($complete_header, 'epk', 'The header parameter "epk" is missing');
        Assertion::isArray($complete_header['epk'], 'The header parameter "epk" is not an array of parameter');

        $public_key = new JWK($complete_header['epk']);
        $this->checkKey($public_key, false);

        return $public_key;
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param bool                      $is_private
     */
    private function checkKey(JWKInterface $key, $is_private)
    {
        Assertion::true($key->has('x'), 'The key parameter "x" is missing.');
        Assertion::true($key->has('crv'), 'The key parameter "crv" is missing.');

        switch ($key->get('crv')) {
            case 'P-256':
            case 'P-384':
            case 'P-521':
                Assertion::eq($key->get('kty'), 'EC', 'Wrong key type.');
                Assertion::true($key->has('y'), 'The key parameter "y" is missing.');

                break;
            case 'X25519':
                Assertion::eq($key->get('kty'), 'OKP', 'Wrong key type.');

                break;
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported', $key->get('crv')));
        }
        if (true === $is_private) {
            Assertion::true($key->has('d'), 'The key parameter "d" is missing.');
        }
    }

    /**
     * @param JWKInterface $key
     *
     * @throws \InvalidArgumentException
     *
     * @return \Mdanter\Ecc\Primitives\GeneratorPoint
     */
    private function getGenerator(JWKInterface $key)
    {
        $crv = $key->get('crv');

        switch ($crv) {
            case 'P-256':
                return EccFactory::getNistCurves()->generator256();
            case 'P-384':
                return EccFactory::getNistCurves()->generator384();
            case 'P-521':
                return EccFactory::getNistCurves()->generator521();
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported', $crv));
        }
    }

    /**
     * @param string $value
     *
     * @return resource
     */
    private function convertBase64ToGmp($value)
    {
        $value = unpack('H*', Base64Url::decode($value));

        return gmp_init($value[1], 16);
    }

    /**
     * @param $value
     *
     * @return string
     */
    private function convertDecToBin($value)
    {
        $value = gmp_strval($value, 10);
        $adapter = EccFactory::getAdapter();

        return hex2bin($adapter->decHex($value));
    }
}
