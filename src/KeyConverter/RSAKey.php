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
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\NullObject;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Jose\Object\JWKInterface;
use Jose\Util\BigInteger;

final class RSAKey extends Sequence
{
    /**
     * @var array
     */
    private $values = [];

    /**
     * @var \Jose\Util\BigInteger
     */
    private $modulus;

    /**
     * @var int
     */
    private $modulus_length;

    /**
     * @var \Jose\Util\BigInteger
     */
    private $public_exponent;

    /**
     * @var \Jose\Util\BigInteger|null
     */
    private $private_exponent = null;

    /**
     * @var \Jose\Util\BigInteger[]
     */
    private $primes = [];

    /**
     * @var \Jose\Util\BigInteger[]
     */
    private $exponents = [];

    /**
     * @var \Jose\Util\BigInteger|null
     */
    private $coefficient = null;

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

        $this->populateBigIntegers();
    }

    /**
     * @return bool
     */
    public function isPublic()
    {
        return !$this->isPrivate();
    }

    /**
     * @return bool
     */
    public function isPrivate()
    {
        return array_key_exists('d', $this->values);
    }

    /**
     * @return \Jose\Util\BigInteger
     */
    public function getModulus()
    {
        return $this->modulus;
    }

    /**
     * @return int
     */
    public function getModulusLength()
    {
        return $this->modulus_length;
    }

    /**
     * @return \Jose\Util\BigInteger
     */
    public function getExponent()
    {
        $d = $this->getPrivateExponent();
        if (null !== $d) {
            return $d;
        }

        return $this->getPublicExponent();
    }

    /**
     * @return \Jose\Util\BigInteger
     */
    public function getPublicExponent()
    {
        return $this->public_exponent;
    }

    /**
     * @return \Jose\Util\BigInteger
     */
    public function getPrivateExponent()
    {
        return $this->private_exponent;
    }

    /**
     * @return \Jose\Util\BigInteger[]
     */
    public function getPrimes()
    {
        return $this->primes;
    }

    /**
     * @return \Jose\Util\BigInteger[]
     */
    public function getExponents()
    {
        return $this->exponents;
    }

    /**
     * @return \Jose\Util\BigInteger|null
     */
    public function getCoefficient()
    {
        return $this->coefficient;
    }

    /**
     * @param \Jose\KeyConverter\RSAKey $private
     *
     * @return \Jose\KeyConverter\RSAKey
     */
    public static function toPublic(self $private)
    {
        $data = $private->toArray();
        $keys = ['p', 'd', 'q', 'dp', 'dq', 'qi'];
        foreach ($keys as $key) {
            if (array_key_exists($key, $data)) {
                unset($data[$key]);
            }
        }

        return new self($data);
    }

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
        $result = '-----BEGIN '.($this->isPrivate() ? 'RSA PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;
        $result .= chunk_split(base64_encode($this->getBinary()), 64, PHP_EOL);
        $result .= '-----END '.($this->isPrivate() ? 'RSA PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;

        return $result;
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
        $res = openssl_pkey_get_private($data);
        if (false === $res) {
            $res = openssl_pkey_get_public($data);
        }
        Assertion::false(false === $res, 'Unable to load the key');

        $details = openssl_pkey_get_details($res);
        Assertion::keyExists($details, 'rsa', 'Unable to load the key');

        $this->values['kty'] = 'RSA';
        $keys = [
            'n' => 'n',
            'e' => 'e',
            'd' => 'd',
            'p' => 'p',
            'q' => 'q',
            'dp' => 'dmp1',
            'dq' => 'dmq1',
            'qi' => 'iqmp',
        ];
        foreach ($details['rsa'] as $key => $value) {
            if (in_array($key, $keys)) {
                $value = Base64Url::encode($value);
                $this->values[array_search($key, $keys)] = $value;
            }
        }
    }

    /**
     * @param array $jwk
     */
    private function loadJWK(array $jwk)
    {
        Assertion::keyExists($jwk, 'kty', 'The key parameter "kty" is missing.');
        Assertion::eq($jwk['kty'], 'RSA', 'The JWK is not a RSA key');

        $this->values = $jwk;
        if (array_key_exists('d', $jwk)) {
            $this->populateCRT();
            $this->initPrivateKey();
        } else {
            $this->initPublicKey();
        }
    }

    /**
     * This method adds Chinese Remainder Theorem (CRT) parameters if primes 'p' and 'q' are available.
     */
    private function populateCRT()
    {
        if (!array_key_exists('p', $this->values) && !array_key_exists('q', $this->values)) {
            $d = BigInteger::createFromBinaryString(Base64Url::decode($this->values['d']));
            $e = BigInteger::createFromBinaryString(Base64Url::decode($this->values['e']));
            $n = BigInteger::createFromBinaryString(Base64Url::decode($this->values['n']));

            list($p, $q) = $this->findPrimeFactors($d, $e, $n);
            $this->values['p'] = Base64Url::encode($p->toBytes());
            $this->values['q'] = Base64Url::encode($q->toBytes());
        }

        if (array_key_exists('dp', $this->values) && array_key_exists('dq', $this->values) && array_key_exists('qi', $this->values)) {
            return;
        }

        $one = BigInteger::createFromDecimal(1);
        $d = BigInteger::createFromBinaryString(Base64Url::decode($this->values['d']));
        $p = BigInteger::createFromBinaryString(Base64Url::decode($this->values['p']));
        $q = BigInteger::createFromBinaryString(Base64Url::decode($this->values['q']));

        $this->values['dp'] = Base64Url::encode($d->mod($p->subtract($one))->toBytes());
        $this->values['dq'] = Base64Url::encode($d->mod($q->subtract($one))->toBytes());
        $this->values['qi'] = Base64Url::encode($q->modInverse($p)->toBytes());
    }

    /**
     * @throws \Exception
     */
    private function initPublicKey()
    {
        $oid_sequence = new Sequence();
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.113549.1.1.1'));
        $oid_sequence->addChild(new NullObject());
        $this->addChild($oid_sequence);

        $n = new Integer($this->fromBase64ToInteger($this->values['n']));
        $e = new Integer($this->fromBase64ToInteger($this->values['e']));

        $key_sequence = new Sequence();
        $key_sequence->addChild($n);
        $key_sequence->addChild($e);
        $key_bit_string = new BitString(bin2hex($key_sequence->getBinary()));
        $this->addChild($key_bit_string);
    }

    private function initPrivateKey()
    {
        $this->addChild(new Integer(0));

        $oid_sequence = new Sequence();
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.113549.1.1.1'));
        $oid_sequence->addChild(new NullObject());
        $this->addChild($oid_sequence);

        $v = new Integer(0);
        $n = new Integer($this->fromBase64ToInteger($this->values['n']));
        $e = new Integer($this->fromBase64ToInteger($this->values['e']));
        $d = new Integer($this->fromBase64ToInteger($this->values['d']));
        $p = new Integer($this->fromBase64ToInteger($this->values['p']));
        $q = new Integer($this->fromBase64ToInteger($this->values['q']));
        $dp = array_key_exists('dp', $this->values) ? new Integer($this->fromBase64ToInteger($this->values['dp'])) : new Integer(0);
        $dq = array_key_exists('dq', $this->values) ? new Integer($this->fromBase64ToInteger($this->values['dq'])) : new Integer(0);
        $qi = array_key_exists('qi', $this->values) ? new Integer($this->fromBase64ToInteger($this->values['qi'])) : new Integer(0);

        $key_sequence = new Sequence();
        $key_sequence->addChild($v);
        $key_sequence->addChild($n);
        $key_sequence->addChild($e);
        $key_sequence->addChild($d);
        $key_sequence->addChild($p);
        $key_sequence->addChild($q);
        $key_sequence->addChild($dp);
        $key_sequence->addChild($dq);
        $key_sequence->addChild($qi);
        $key_octet_string = new OctetString(bin2hex($key_sequence->getBinary()));
        $this->addChild($key_octet_string);
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private function fromBase64ToInteger($value)
    {
        return gmp_strval(gmp_init(current(unpack('H*', Base64Url::decode($value))), 16), 10);
    }

    private function populateBigIntegers()
    {
        $this->modulus = $this->convertBase64StringToBigInteger($this->values['n']);
        $this->modulus_length = mb_strlen($this->getModulus()->toBytes(), '8bit');
        $this->public_exponent = $this->convertBase64StringToBigInteger($this->values['e']);

        if (true === $this->isPrivate()) {
            $this->private_exponent = $this->convertBase64StringToBigInteger($this->values['d']);

            if (array_key_exists('p', $this->values) && array_key_exists('q', $this->values)) {
                $this->primes = [
                    $this->convertBase64StringToBigInteger($this->values['p']),
                    $this->convertBase64StringToBigInteger($this->values['q']),
                ];
                $this->exponents = [
                    $this->convertBase64StringToBigInteger($this->values['dp']),
                    $this->convertBase64StringToBigInteger($this->values['dq']),
                ];
                $this->coefficient = $this->convertBase64StringToBigInteger($this->values['qi']);
            }
        }
    }

    /**
     * @param string $value
     *
     * @return \Jose\Util\BigInteger
     */
    private function convertBase64StringToBigInteger($value)
    {
        return BigInteger::createFromBinaryString(Base64Url::decode($value));
    }

    /**
     * @param BigInteger $d
     * @param BigInteger $e
     * @param BigInteger $n
     *
     * @return array
     */
    private function findPrimeFactors(BigInteger $d, BigInteger $e, BigInteger $n)
    {
        $zero = BigInteger::createFromDecimal(0);
        $one = BigInteger::createFromDecimal(1);
        $two = BigInteger::createFromDecimal(2);

        $k = $d->multiply($e)->subtract($one);

        if ($k->isEven()) {
            $r = $k;
            $t = $zero;

            do {
                $r = $r->divide($two);
                $t = $t->add($one);
            } while ($r->isEven());

            $found = false;
            $y = null;

            for ($i = 1; $i <= 100; ++$i) {
                $g = BigInteger::random($n->subtract($one));
                $y = $g->modPow($r, $n);

                if ($y->equals($one) || $y->equals($n->subtract($one))) {
                    continue;
                }

                for ($j = $one; $j->lowerThan($t->subtract($one)); $j = $j->add($one)) {
                    $x = $y->modPow($two, $n);

                    if ($x->equals($one)) {
                        $found = true;

                        break;
                    }

                    if ($x->equals($n->subtract($one))) {
                        continue;
                    }

                    $y = $x;
                }

                $x = $y->modPow($two, $n);
                if ($x->equals($one)) {
                    $found = true;

                    break;
                }
            }

            if (true === $found) {
                $p = $y->subtract($one)->gcd($n);
                $q = $n->divide($p);

                return [$p, $q];
            }
        }

        throw new \InvalidArgumentException('Unable to find prime factors.');
    }
}
