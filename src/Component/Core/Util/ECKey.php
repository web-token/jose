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

namespace Jose\Component\Core\Util;

use Assert\Assertion;
use Base64Url\Base64Url;
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Jose\Component\Core\JWK;

final class ECKey
{
    /**
     * @var null|Sequence
     */
    private $sequence = null;

    /**
     * @var bool
     */
    private $private = false;

    /**
     * @var array
     */
    private $values = [];

    /**
     * ECKey constructor.
     *
     * @param JWK $data
     */
    private function __construct(JWK $data)
    {
        $this->sequence = new Sequence();
        $this->loadJWK($data->all());
        $this->private = isset($this->values['d']);
    }

    /**
     * @param JWK $jwk
     *
     * @return ECKey
     */
    public static function createFromJWK(JWK $jwk): ECKey
    {
        return new self($jwk);
    }

    /**
     * @param array $jwk
     */
    private function loadJWK(array $jwk)
    {
        Assertion::true(array_key_exists('kty', $jwk), 'JWK is not an Elliptic Curve key');
        Assertion::eq($jwk['kty'], 'EC', 'JWK is not an Elliptic Curve key');
        Assertion::true(array_key_exists('crv', $jwk), 'Curve parameter is missing');
        Assertion::true(array_key_exists('x', $jwk), 'Point parameters are missing');
        Assertion::true(array_key_exists('y', $jwk), 'Point parameters are missing');

        $this->values = $jwk;
        if (array_key_exists('d', $jwk)) {
            $this->initPrivateKey();
        } else {
            $this->initPublicKey();
        }
    }

    private function initPublicKey()
    {
        $oid_sequence = new Sequence();
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.10045.2.1'));
        $oid_sequence->addChild(new ObjectIdentifier($this->getOID($this->values['crv'])));
        $this->sequence->addChild($oid_sequence);

        $bits = '04';
        $bits .= bin2hex(Base64Url::decode($this->values['x']));
        $bits .= bin2hex(Base64Url::decode($this->values['y']));
        $this->sequence->addChild(new BitString($bits));
    }

    private function initPrivateKey()
    {
        $this->sequence->addChild(new Integer(1));
        $this->sequence->addChild(new OctetString(bin2hex(Base64Url::decode($this->values['d']))));

        $oid = new ObjectIdentifier($this->getOID($this->values['crv']));
        $this->sequence->addChild(new ExplicitlyTaggedObject(0, $oid));

        $bits = '04';
        $bits .= bin2hex(Base64Url::decode($this->values['x']));
        $bits .= bin2hex(Base64Url::decode($this->values['y']));
        $bit = new BitString($bits);
        $this->sequence->addChild(new ExplicitlyTaggedObject(1, $bit));
    }

    /**
     * @return string
     */
    public function toPEM(): string
    {
        $result = '-----BEGIN '.($this->private ? 'EC PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;
        $result .= chunk_split(base64_encode($this->sequence->getBinary()), 64, PHP_EOL);
        $result .= '-----END '.($this->private ? 'EC PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;

        return $result;
    }

    /**
     * @param $curve
     *
     * @return string
     */
    private function getOID(string $curve): string
    {
        $curves = $this->getSupportedCurves();
        $oid = array_key_exists($curve, $curves) ? $curves[$curve] : null;

        Assertion::notNull($oid, 'Unsupported curve');

        return $oid;
    }

    /**
     * @return array
     */
    private function getSupportedCurves(): array
    {
        return [
            'P-256' => '1.2.840.10045.3.1.7',
            'P-384' => '1.3.132.0.34',
            'P-521' => '1.3.132.0.35',
        ];
    }
}
