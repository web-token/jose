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

namespace Jose\Component\KeyManagement\KeyConverter;

use Base64Url\Base64Url;
use FG\ASN1\Exception\ParserException;
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Object;
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
     * @param $data
     */
    private function __construct($data)
    {
        $this->sequence = new Sequence();

        if ($data instanceof JWK) {
            $this->loadJWK($data->all());
        } elseif (is_array($data)) {
            $this->loadJWK($data);
        } elseif (is_string($data)) {
            $this->loadPEM($data);
        } else {
            throw new \InvalidArgumentException('Unsupported input');
        }
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
     * @param string $pem
     *
     * @return ECKey
     */
    public static function createFromPEM(string $pem): ECKey
    {
        return new self($pem);
    }

    /**
     * @param string $data
     *
     * @throws \Exception
     * @throws ParserException
     */
    private function loadPEM(string $data)
    {
        $data = base64_decode(preg_replace('#-.*-|\r|\n#', '', $data));
        $asnObject = Object::fromBinary($data);

        if (!$asnObject instanceof Sequence) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }
        $children = $asnObject->getChildren();
        if (self::isPKCS8($children)) {
            $children = self::loadPKCS8($children);
        }

        if (4 === count($children)) {
            $this->loadPrivatePEM($children);

            return;
        } elseif (2 === count($children)) {
            $this->loadPublicPEM($children);

            return;
        }

        throw new \Exception('Unable to load the key.');
    }

    /**
     * @param array $children
     *
     * @return array
     */
    private function loadPKCS8(array $children): array
    {
        $binary = hex2bin($children[2]->getContent());
        $asnObject = Object::fromBinary($binary);
        if (!$asnObject instanceof Sequence) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        return $asnObject->getChildren();
    }

    /**
     * @param array $children
     *
     * @return bool
     */
    private function isPKCS8(array $children): bool
    {
        if (3 !== count($children)) {
            return false;
        }

        $classes = [0 => Integer::class, 1 => Sequence::class, 2 => OctetString::class];
        foreach ($classes as $k => $class) {
            if (!$children[$k] instanceof $class) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array $jwk
     */
    private function loadJWK(array $jwk)
    {
        foreach (['kty', 'x', 'y', 'crv'] as $k) {
            if (!array_key_exists($k, $jwk)) {
                throw new \InvalidArgumentException(sprintf('The key parameter "%s" is missing.', $k));
            }
        }
        if ('EC' !== $jwk['kty']) {
            throw new \InvalidArgumentException('JWK is not an Elliptic Curve key');
        }

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
     * @param array $children
     *
     * @throws \Exception
     */
    private function loadPublicPEM(array $children)
    {
        if (!$children[0] instanceof Sequence) {
            throw new \InvalidArgumentException('Unsupported key type.');
        }

        $sub = $children[0]->getChildren();
        if (!$sub[0] instanceof ObjectIdentifier) {
            throw new \InvalidArgumentException('Unsupported key type.');
        }
        if ('1.2.840.10045.2.1' !== $sub[0]->getContent()) {
            throw new \InvalidArgumentException('Unsupported key type.');
        }
        if (!$sub[1] instanceof ObjectIdentifier) {
            throw new \InvalidArgumentException('Unsupported key type.');
        }
        if (!$children[1] instanceof BitString) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        $bits = $children[1]->getContent();
        $bits_length = mb_strlen($bits, '8bit');
        if ('04' !== mb_substr($bits, 0, 2, '8bit')) {
            throw new \InvalidArgumentException('Unsupported key type');
        }

        $this->values['kty'] = 'EC';
        $this->values['crv'] = $this->getCurve($sub[1]->getContent());
        $this->values['x'] = Base64Url::encode(hex2bin(mb_substr($bits, 2, ($bits_length - 2) / 2, '8bit')));
        $this->values['y'] = Base64Url::encode(hex2bin(mb_substr($bits, ($bits_length - 2) / 2 + 2, ($bits_length - 2) / 2, '8bit')));
    }

    /**
     * @param object $children
     */
    private function verifyVersion(Object $children)
    {
        if (!$children instanceof Integer || '1' !== $children->getContent()) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }
    }

    /**
     * @param object      $children
     * @param string|null $x
     * @param string|null $y
     */
    private function getXAndY(Object $children, ?string &$x, ?string &$y)
    {
        if (!$children instanceof ExplicitlyTaggedObject || !is_array($children->getContent())) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }
        if (!$children->getContent()[0] instanceof BitString) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        $bits = $children->getContent()[0]->getContent();
        $bits_length = mb_strlen($bits, '8bit');

        if ('04' !== mb_substr($bits, 0, 2, '8bit')) {
            throw new \InvalidArgumentException('Unsupported key type');
        }

        $x = mb_substr($bits, 2, ($bits_length - 2) / 2, '8bit');
        $y = mb_substr($bits, ($bits_length - 2) / 2 + 2, ($bits_length - 2) / 2, '8bit');
    }

    /**
     * @param object $children
     *
     * @return string
     */
    private function getD(Object $children): string
    {
        if (!$children instanceof OctetString) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        return $children->getContent();
    }

    /**
     * @param array $children
     */
    private function loadPrivatePEM(array $children)
    {
        $this->verifyVersion($children[0]);
        $x = null;
        $y = null;
        $d = $this->getD($children[1]);
        $this->getXAndY($children[3], $x, $y);

        if (!$children[2] instanceof ExplicitlyTaggedObject || !is_array($children[2]->getContent())) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }
        if (!$children[2]->getContent()[0] instanceof ObjectIdentifier) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        $curve = $children[2]->getContent()[0]->getContent();

        $this->private = true;
        $this->values['kty'] = 'EC';
        $this->values['crv'] = $this->getCurve($curve);
        $this->values['d'] = Base64Url::encode(hex2bin($d));
        $this->values['x'] = Base64Url::encode(hex2bin($x));
        $this->values['y'] = Base64Url::encode(hex2bin($y));
    }

    /**
     * @param ECKey $private
     *
     * @return ECKey
     */
    public static function toPublic(ECKey $private): ECKey
    {
        $data = $private->toArray();
        if (array_key_exists('d', $data)) {
            unset($data['d']);
        }

        return new self($data);
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return $this->values;
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
        if (!is_string($oid)) {
            throw new \InvalidArgumentException('Unsupported curve.');
        }

        return $oid;
    }

    /**
     * @param string $oid
     *
     * @return string
     */
    private function getCurve(string $oid): string
    {
        $curves = $this->getSupportedCurves();
        $curve = array_search($oid, $curves, true);
        if (!is_string($curve)) {
            throw new \InvalidArgumentException('Unsupported OID.');
        }

        return $curve;
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
