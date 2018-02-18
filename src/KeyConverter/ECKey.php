<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\KeyConverter;

use Assert\Assertion;
use Base64Url\Base64Url;
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Object;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Jose\Object\JWKInterface;

final class ECKey extends Sequence
{
    /**
     * @var bool
     */
    private $private = false;

    /**
     * @var array
     */
    private $values = [];

    /**
     * @param \Jose\Object\JWKInterface|string|array $data
     */
    public function __construct($data)
    {
        parent::__construct();

        if ($data instanceof JWKInterface) {
            $this->loadJWK($data->getAll());
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
     * @param string $data
     *
     * @throws \Exception
     * @throws \FG\ASN1\Exception\ParserException
     *
     * @return array
     */
    private function loadPEM($data)
    {
        $data = base64_decode(preg_replace('#-.*-|\r|\n#', '', $data));
        $asnObject = Object::fromBinary($data);

        Assertion::isInstanceOf($asnObject, Sequence::class);
        $children = $asnObject->getChildren();
        if (self::isPKCS8($children)) {
            $children = self::loadPKCS8($children);
        }

        if (4 === count($children)) {
            return $this->loadPrivatePEM($children);
        } elseif (2 === count($children)) {
            return $this->loadPublicPEM($children);
        }

        throw new \Exception('Unable to load the key');
    }

    /**
     * @param array $children
     *
     * @return array
     */
    private function loadPKCS8(array $children)
    {
        $binary = hex2bin($children[2]->getContent());
        $asnObject = Object::fromBinary($binary);
        Assertion::isInstanceOf($asnObject, Sequence::class);

        return $asnObject->getChildren();
    }

    /**
     * @param array $children
     *
     * @return bool
     */
    private function isPKCS8(array $children)
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
        $this->addChild($oid_sequence);

        $bits = '04';
        $bits .= bin2hex(Base64Url::decode($this->values['x']));
        $bits .= bin2hex(Base64Url::decode($this->values['y']));
        $this->addChild(new BitString($bits));
    }

    private function initPrivateKey()
    {
        $this->addChild(new Integer(1));
        $this->addChild(new OctetString(bin2hex(Base64Url::decode($this->values['d']))));

        $oid = new ObjectIdentifier($this->getOID($this->values['crv']));
        $this->addChild(new ExplicitlyTaggedObject(0, $oid));

        $bits = '04';
        $bits .= bin2hex(Base64Url::decode($this->values['x']));
        $bits .= bin2hex(Base64Url::decode($this->values['y']));
        $bit = new BitString($bits);
        $this->addChild(new ExplicitlyTaggedObject(1, $bit));
    }

    /**
     * @param array $children
     *
     * @throws \Exception
     *
     * @return array
     */
    private function loadPublicPEM(array $children)
    {
        Assertion::isInstanceOf($children[0], Sequence::class, 'Unsupported key type');

        $sub = $children[0]->getChildren();
        Assertion::isInstanceOf($sub[0], ObjectIdentifier::class, 'Unsupported key type');
        Assertion::eq('1.2.840.10045.2.1', $sub[0]->getContent(), 'Unsupported key type');

        Assertion::isInstanceOf($sub[1], ObjectIdentifier::class, 'Unsupported key type');
        Assertion::isInstanceOf($children[1], BitString::class, 'Unable to load the key');

        $bits = $children[1]->getContent();
        $bits_length = mb_strlen($bits, '8bit');

        Assertion::eq('04', mb_substr($bits, 0, 2, '8bit'), 'Unsupported key type');

        $this->values['kty'] = 'EC';
        $this->values['crv'] = $this->getCurve($sub[1]->getContent());
        $this->values['x'] = Base64Url::encode(hex2bin(mb_substr($bits, 2, ($bits_length - 2) / 2, '8bit')));
        $this->values['y'] = Base64Url::encode(hex2bin(mb_substr($bits, ($bits_length - 2) / 2 + 2, ($bits_length - 2) / 2, '8bit')));
    }

    /**
     * @param \FG\ASN1\Object $children
     */
    private function verifyVersion(Object $children)
    {
        Assertion::isInstanceOf($children, Integer::class, 'Unable to load the key');
        Assertion::eq(1, $children->getContent(), 'Unable to load the key');
    }

    /**
     * @param \FG\ASN1\Object $children
     * @param string|null     $x
     * @param string|null     $y
     */
    private function getXAndY(Object $children, &$x, &$y)
    {
        Assertion::isInstanceOf($children, ExplicitlyTaggedObject::class, 'Unable to load the key');
        Assertion::isArray($children->getContent(), 'Unable to load the key');
        Assertion::isInstanceOf($children->getContent()[0], BitString::class, 'Unable to load the key');

        $bits = $children->getContent()[0]->getContent();
        $bits_length = mb_strlen($bits, '8bit');

        Assertion::eq('04', mb_substr($bits, 0, 2, '8bit'), 'Unsupported key type');

        $x = mb_substr($bits, 2, ($bits_length - 2) / 2, '8bit');
        $y = mb_substr($bits, ($bits_length - 2) / 2 + 2, ($bits_length - 2) / 2, '8bit');
    }

    /**
     * @param \FG\ASN1\Object $children
     *
     * @return string
     */
    private function getD(Object $children)
    {
        Assertion::isInstanceOf($children, '\FG\ASN1\Universal\OctetString', 'Unable to load the key');

        return $children->getContent();
    }

    /**
     * @param array $children
     *
     * @return array
     */
    private function loadPrivatePEM(array $children)
    {
        $this->verifyVersion($children[0]);
        $x = null;
        $y = null;
        $d = $this->getD($children[1]);
        $this->getXAndY($children[3], $x, $y);

        Assertion::isInstanceOf($children[2], ExplicitlyTaggedObject::class, 'Unable to load the key');
        Assertion::isArray($children[2]->getContent(), 'Unable to load the key');
        Assertion::isInstanceOf($children[2]->getContent()[0], ObjectIdentifier::class, 'Unable to load the key');

        $curve = $children[2]->getContent()[0]->getContent();

        $this->private = true;
        $this->values['kty'] = 'EC';
        $this->values['crv'] = $this->getCurve($curve);
        $this->values['d'] = Base64Url::encode(hex2bin($d));
        $this->values['x'] = Base64Url::encode(hex2bin($x));
        $this->values['y'] = Base64Url::encode(hex2bin($y));
    }

    /**
     * @return bool
     */
    public function isPrivate()
    {
        return $this->private;
    }

    /**
     * @param \Jose\KeyConverter\ECKey $private
     *
     * @return \Jose\KeyConverter\ECKey
     */
    public static function toPublic(self $private)
    {
        $data = $private->toArray();
        if (array_key_exists('d', $data)) {
            unset($data['d']);
        }

        return new self($data);
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toPEM();
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
    public function toDER()
    {
        return $this->getBinary();
    }

    /**
     * @return string
     */
    public function toPEM()
    {
        $result = '-----BEGIN '.($this->private ? 'EC PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;
        $result .= chunk_split(base64_encode($this->getBinary()), 64, PHP_EOL);
        $result .= '-----END '.($this->private ? 'EC PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;

        return $result;
    }

    /**
     * @param $curve
     *
     * @return string
     */
    private function getOID($curve)
    {
        $curves = $this->getSupportedCurves();
        $oid = array_key_exists($curve, $curves) ? $curves[$curve] : null;

        Assertion::notNull($oid, 'Unsupported curve');

        return $oid;
    }

    /**
     * @param string $oid
     *
     * @return string
     */
    private function getCurve($oid)
    {
        $curves = $this->getSupportedCurves();
        $curve = array_search($oid, $curves, true);
        Assertion::string($curve, 'Unsupported OID');

        return $curve;
    }

    /**
     * @return array
     */
    private function getSupportedCurves()
    {
        return [
            'P-256' => '1.2.840.10045.3.1.7',
            'P-384' => '1.3.132.0.34',
            'P-521' => '1.3.132.0.35',
        ];
    }
}
