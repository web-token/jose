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

namespace Jose\Component\Signature\Algorithm;

use FG\ASN1\ASNObject;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\Sequence;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Signature\SignatureAlgorithmInterface;
use Jose\Component\Core\Util\Ecc\EccFactory;

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
        if (!$key->has('d')) {
            throw new \InvalidArgumentException('The EC key is not private');
        }

        $eckey = ECKey::createFromJWK($key);
        $result = openssl_sign($input, $signature, $eckey->toPEM(), $this->getHashAlgorithm());
        if (false === $result) {
            throw new \RuntimeException('Signature failed.');
        }

        $asn = ASNObject::fromBinary($signature);
        if (!$asn instanceof Sequence) {
            throw new \RuntimeException('Invalid signature');
        }

        $res = '';
        foreach ($asn->getChildren() as $child) {
            if (!$child instanceof Integer) {
                throw new \RuntimeException('Invalid signature');
            }
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

        $oid_sequence = new Sequence();
        $oid_sequence->addChildren([
            new Integer(gmp_strval($this->convertHexToGmp($R), 10)),
            new Integer(gmp_strval($this->convertHexToGmp($S), 10)),
        ]);
        $eckey = ECKey::toPublic(ECKey::createFromJWK($key));

        return 1 === openssl_verify($input, $oid_sequence->getBinary(), $eckey->toPEM(), $this->getHashAlgorithm());
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
        $adapter = new GmpMath();

        return $adapter->decHex($value);
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
        if ('EC' !== $key->get('kty')) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        foreach (['x', 'y', 'crv'] as $k) {
            if (!$key->has($k)) {
                throw new \InvalidArgumentException(sprintf('The key parameter "%s" is missing.', $k));
            }
        }
    }
}
