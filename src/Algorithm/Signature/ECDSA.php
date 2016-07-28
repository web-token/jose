<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

use Assert\Assertion;
use Base64Url\Base64Url;
use FG\ASN1\Object;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\Sequence;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\KeyConverter\ECKey;
use Jose\Object\JWKInterface;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Random\RandomGeneratorFactory;

/**
 * Class ECDSA.
 */
abstract class ECDSA implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $data)
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The EC key is not private');

        if (defined('OPENSSL_KEYTYPE_EC')) {
            return $this->getOpenSSLSignature($key, $data);
        }

        return $this->getPHPECCSignature($key, $data);
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $data
     *
     * @return string
     */
    private function getOpenSSLSignature(JWKInterface $key, $data)
    {
        $pem = (new ECKey($key))->toPEM();
        $result = openssl_sign($data, $signature, $pem, $this->getHashAlgorithm());

        Assertion::true($result, 'Signature failed');

        $asn = Object::fromBinary($signature);
        Assertion::isInstanceOf($asn, Sequence::class, 'Invalid signature');

        $res = '';
        foreach ($asn->getChildren() as $child) {
            Assertion::isInstanceOf($child, Integer::class, 'Invalid signature');
            $res .= str_pad($this->convertDecToHex($child->getContent()), $this->getSignaturePartLength(), '0', STR_PAD_LEFT);
        }

        return $this->convertHexToBin($res);
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $data
     *
     * @return string
     */
    private function getPHPECCSignature(JWKInterface $key, $data)
    {
        $p = $this->getGenerator();
        $d = $this->convertBase64ToGmp($key->get('d'));
        $hash = $this->convertHexToGmp(hash($this->getHashAlgorithm(), $data));

        $k = RandomGeneratorFactory::getRandomGenerator()->generate($p->getOrder());

        $signer = EccFactory::getSigner();

        $private_key = $p->getPrivateKeyFrom($d);
        $signature = $signer->sign($private_key, $hash, $k);

        $part_length = $this->getSignaturePartLength();

        $R = str_pad($this->convertDecToHex($signature->getR()), $part_length, '0', STR_PAD_LEFT);
        $S = str_pad($this->convertDecToHex($signature->getS()), $part_length, '0', STR_PAD_LEFT);

        return $this->convertHexToBin($R.$S);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, $data, $signature)
    {
        $this->checkKey($key);

        $signature = $this->convertBinToHex($signature);
        $part_length = $this->getSignaturePartLength();
        if (mb_strlen($signature, '8bit') !== 2 * $part_length) {
            return false;
        }
        $R = mb_substr($signature, 0, $part_length, '8bit');
        $S = mb_substr($signature, $part_length, null, '8bit');

        if (defined('OPENSSL_KEYTYPE_EC')) {
            return $this->verifyOpenSSLSignature($key, $data, $R, $S);
        }

        return $this->verifyPHPECCSignature($key, $data, $R, $S);
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $data
     * @param string                    $R
     * @param string                    $S
     *
     * @return bool
     */
    private function verifyOpenSSLSignature(JWKInterface $key, $data, $R, $S)
    {
        $pem = ECKey::toPublic(new ECKey($key))->toPEM();

        $oid_sequence = new Sequence();
        $oid_sequence->addChildren([
            new Integer(gmp_strval($this->convertHexToGmp($R), 10)),
            new Integer(gmp_strval($this->convertHexToGmp($S), 10)),
        ]);

        return 1 === openssl_verify($data, $oid_sequence->getBinary(), $pem, $this->getHashAlgorithm());
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $data
     * @param string                    $R
     * @param string                    $S
     *
     * @return bool
     */
    private function verifyPHPECCSignature(JWKInterface $key, $data, $R, $S)
    {
        $p = $this->getGenerator();
        $x = $this->convertBase64ToGmp($key->get('x'));
        $y = $this->convertBase64ToGmp($key->get('y'));
        $hash = $this->convertHexToGmp(hash($this->getHashAlgorithm(), $data));

        $public_key = $p->getPublicKeyFrom($x, $y);

        $signer = EccFactory::getSigner();

        return $signer->verify(
            $public_key,
            new Signature(
                $this->convertHexToGmp($R),
                $this->convertHexToGmp($S)
            ),
            $hash
        );
    }

    /**
     * @return \Mdanter\Ecc\Primitives\GeneratorPoint
     */
    abstract protected function getGenerator();

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();

    /**
     * @return int
     */
    abstract protected function getSignaturePartLength();

    /**
     * @param string $value
     *
     * @return string
     */
    private function convertHexToBin($value)
    {
        return pack('H*', $value);
    }

    /**
     * @param string $value
     */
    private function convertBinToHex($value)
    {
        $value = unpack('H*', $value);

        return $value[1];
    }

    /**
     * @param $value
     *
     * @return string
     */
    private function convertDecToHex($value)
    {
        $value = gmp_strval($value, 10);

        return EccFactory::getAdapter()->decHex($value);
    }

    /**
     * @param string $value
     *
     * @return resource
     */
    private function convertHexToGmp($value)
    {
        return gmp_init($value, 16);
    }

    /**
     * @param $value
     *
     * @return resource
     */
    private function convertBase64ToGmp($value)
    {
        $value = unpack('H*', Base64Url::decode($value));

        return gmp_init($value[1], 16);
    }

    /**
     * @param JWKInterface $key
     */
    private function checkKey(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'EC', 'Wrong key type.');
        Assertion::true($key->has('x'), 'The key parameter "x" is missing.');
        Assertion::true($key->has('y'), 'The key parameter "y" is missing.');
        Assertion::true($key->has('crv'), 'The key parameter "crv" is missing.');
    }
}
