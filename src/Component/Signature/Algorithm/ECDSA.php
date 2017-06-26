<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Algorithm;

use Assert\Assertion;
use FG\ASN1\Object;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\Sequence;
use Jose\Component\Signature\SignatureAlgorithmInterface;
use Jose\Component\KeyManagement\KeyConverter\ECKey;
use Jose\Component\Core\JWK;
use Mdanter\Ecc\EccFactory;

/**
 * Class ECDSA.
 */
abstract class ECDSA implements SignatureAlgorithmInterface
{
    /**
     * ECDSA constructor.
     */
    public function __construct()
    {
        if (!defined('OPENSSL_KEYTYPE_EC')) {
            throw new \RuntimeException('Elliptic Curve key type not supported by your environment.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The EC key is not private');

        return $this->getOpenSSLSignature($key, $input);
    }

    /**
     * @param JWK    $key
     * @param string $data
     *
     * @return string
     */
    private function getOpenSSLSignature(JWK $key, $data)
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
     * {@inheritdoc}
     */
    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);

        $signature = $this->convertBinToHex($signature);
        $part_length = $this->getSignaturePartLength();
        if (mb_strlen($signature, '8bit') !== 2 * $part_length) {
            return false;
        }
        $R = mb_substr($signature, 0, $part_length, '8bit');
        $S = mb_substr($signature, $part_length, null, '8bit');

        return $this->verifyOpenSSLSignature($key, $input, $R, $S);
    }

    /**
     * @param JWK    $key
     * @param string $data
     * @param string $R
     * @param string $S
     *
     * @return bool
     */
    private function verifyOpenSSLSignature(JWK $key, $data, $R, $S)
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
     * @return string
     */
    abstract protected function getHashAlgorithm(): string;

    /**
     * @return int
     */
    abstract protected function getSignaturePartLength(): int;

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
     * @param JWK $key
     */
    private function checkKey(JWK $key)
    {
        Assertion::eq($key->get('kty'), 'EC', 'Wrong key type.');
        Assertion::true($key->has('x'), 'The key parameter "x" is missing.');
        Assertion::true($key->has('y'), 'The key parameter "y" is missing.');
        Assertion::true($key->has('crv'), 'The key parameter "crv" is missing.');
    }
}
