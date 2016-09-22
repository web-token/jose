<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\KeyConverter\KeyConverter;
use Jose\KeyConverter\RSAKey;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Object\RotatableJWK;
use Jose\Object\RotatableJWKSet;
use Jose\Object\StorableJWK;
use Jose\Object\StorableJWKSet;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\NistCurve;
use Mdanter\Ecc\EccFactory;
use Psr\Cache\CacheItemPoolInterface;

final class JWKFactory implements JWKFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public static function createStorableKey($filename, array $parameters)
    {
        return new StorableJWK($filename, $parameters);
    }

    /**
     * {@inheritdoc}
     */
    public static function createRotatableKey($filename, array $parameters, $ttl)
    {
        return new RotatableJWK($filename, $parameters, $ttl);
    }

    /**
     * {@inheritdoc}
     */
    public static function createRotatableKeySet($filename, array $parameters, $nb_keys, $ttl)
    {
        return new RotatableJWKSet($filename, $parameters, $nb_keys, $ttl);
    }

    /**
     * {@inheritdoc}
     */
    public static function createStorableKeySet($filename, array $parameters, $nb_keys)
    {
        return new StorableJWKSet($filename, $parameters, $nb_keys);
    }

    /**
     * {@inheritdoc}
     */
    public static function createKey(array $config)
    {
        Assertion::keyExists($config, 'kty', 'The key "kty" must be set');
        $supported_types = ['RSA' => 'RSA', 'OKP' => 'OKP', 'EC' => 'EC', 'oct' => 'Oct', 'none' => 'None'];
        $kty = $config['kty'];
        Assertion::keyExists($supported_types, $kty, sprintf('The key type "%s" is not supported. Please use one of %s', $kty, json_encode(array_keys($supported_types))));
        $method = sprintf('create%sKey', $supported_types[$kty]);

        return self::$method($config);
    }

    /**
     * {@inheritdoc}
     */
    public static function createRSAKey(array $values)
    {
        Assertion::keyExists($values, 'size', 'The key size is not set.');
        $size = $values['size'];
        unset($values['size']);

        Assertion::true(0 === $size % 8, 'Invalid key size.');
        Assertion::greaterOrEqualThan($size, 384, 'Key length is too short. It needs to be at least 384 bits.');

        $key = openssl_pkey_new([
            'private_key_bits' => $size,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $out);
        $rsa = new RSAKey($out);
        $values = array_merge(
            $values,
            $rsa->toArray()
        );

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createECKey(array $values)
    {
        Assertion::keyExists($values, 'crv', 'The curve is not set.');
        $curve = $values['crv'];
        $curve_name = self::getNistName($curve);
        $generator = CurveFactory::getGeneratorByName($curve_name);
        $private_key = $generator->createPrivateKey();

        $values = array_merge(
            $values,
            [
                'kty' => 'EC',
                'crv' => $curve,
                'x'   => self::encodeValue($private_key->getPublicKey()->getPoint()->getX()),
                'y'   => self::encodeValue($private_key->getPublicKey()->getPoint()->getY()),
                'd'   => self::encodeValue($private_key->getSecret()),
            ]
        );

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createOctKey(array $values)
    {
        Assertion::keyExists($values, 'size', 'The key size is not set.');
        $size = $values['size'];
        unset($values['size']);
        Assertion::true(0 === $size % 8, 'Invalid key size.');
        $values = array_merge(
            $values,
            [
                'kty' => 'oct',
                'k'   => Base64Url::encode(random_bytes($size / 8)),
            ]
        );

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createOKPKey(array $values)
    {
        Assertion::keyExists($values, 'crv', 'The curve is not set.');
        $curve = $values['crv'];
        switch ($curve) {
            case 'X25519':
                Assertion::true(function_exists('curve25519_public'), sprintf('Unsupported "%s" curve', $curve));
                $d = random_bytes(32);
                $x = curve25519_public($d);
                break;
            case 'Ed25519':
                Assertion::true(function_exists('ed25519_publickey'), sprintf('Unsupported "%s" curve', $curve));
                $d = random_bytes(32);
                $x = ed25519_publickey($d);
                break;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported "%s" curve', $curve));
        }

        $values = array_merge(
            $values,
            [
                'kty' => 'OKP',
                'crv' => $curve,
                'x'   => Base64Url::encode($x),
                'd'   => Base64Url::encode($d),
            ]
        );

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createNoneKey(array $values)
    {
        $values = array_merge(
            $values,
            [
                'kty' => 'none',
                'alg' => 'none',
                'use' => 'sig',
            ]
        );

        return new JWK($values);
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private static function encodeValue($value)
    {
        $value = gmp_strval($value);

        return Base64Url::encode(self::convertDecToBin($value));
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private static function convertDecToBin($value)
    {
        $adapter = EccFactory::getAdapter();

        return hex2bin($adapter->decHex($value));
    }

    /**
     * @param string $curve
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getNistName($curve)
    {
        switch ($curve) {
            case 'P-256':
                return NistCurve::NAME_P256;
            case 'P-384':
                return NistCurve::NAME_P384;
            case 'P-521':
                return NistCurve::NAME_P521;
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve));
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromValues(array $values)
    {
        if (array_key_exists('keys', $values) && is_array($values['keys'])) {
            return new JWKSet($values);
        }

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromCertificateFile($file, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromCertificateFile($file);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromCertificate($certificate, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromCertificate($certificate);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromX509Resource($res, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromX509Resource($res);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromKeyFile($file, $password = null, array $additional_values = [])
    {
        $values = KeyConverter::loadFromKeyFile($file, $password);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromKey($key, $password = null, array $additional_values = [])
    {
        $values = KeyConverter::loadFromKey($key, $password);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromJKU($jku, $allow_unsecured_connection = false, CacheItemPoolInterface $cache = null)
    {
        $content = self::getContent($jku, $allow_unsecured_connection, $cache);

        Assertion::keyExists($content, 'keys', 'Invalid content.');

        return new JWKSet($content);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromX5U($x5u, $allow_unsecured_connection = false, CacheItemPoolInterface $cache = null)
    {
        $content = self::getContent($x5u, $allow_unsecured_connection, $cache);

        $jwkset = new JWKSet();
        foreach ($content as $kid => $cert) {
            $jwk = KeyConverter::loadKeyFromCertificate($cert);
            Assertion::notEmpty($jwk, 'Invalid content.');
            if (is_string($kid)) {
                $jwk['kid'] = $kid;
            }
            $jwkset->addKey(new JWK($jwk));
        }

        return $jwkset;
    }

    /**
     * @param string                                 $url
     * @param bool                                   $allow_unsecured_connection
     * @param \Psr\Cache\CacheItemPoolInterface|null $cache
     * @param int                                    $ttl
     *
     * @return array
     */
    private static function getContent($url, $allow_unsecured_connection, CacheItemPoolInterface $cache = null, $ttl = 300)
    {
        $cache_key = sprintf('JWKFactory-Content-%s', hash('sha512', $url));
        if (null !== $cache) {
            $item = $cache->getItem($cache_key);
            if (!$item->isHit()) {
                $content = self::downloadContent($url, $allow_unsecured_connection);
                $item->set($content);
                $item->expiresAfter($ttl);
                $cache->save($item);

                return $content;
            } else {
                return $item->get();
            }
        }

        return self::downloadContent($url, $allow_unsecured_connection);
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromX5C(array $x5c, array $additional_values = [])
    {
        $values = KeyConverter::loadFromX5C($x5c);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param string $url
     * @param bool   $allow_unsecured_connection
     *
     * @throws \InvalidArgumentException
     *
     * @return array
     */
    private static function downloadContent($url, $allow_unsecured_connection)
    {
        // The URL must be a valid URL and scheme must be https
        Assertion::false(
            false === filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED),
            'Invalid URL.'
        );
        Assertion::false(
            false === $allow_unsecured_connection && 'https://' !== mb_substr($url, 0, 8, '8bit'),
            'Unsecured connection.'
        );

        $params = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL            => $url,
        ];
        if (false === $allow_unsecured_connection) {
            $params[CURLOPT_SSL_VERIFYPEER] = true;
            $params[CURLOPT_SSL_VERIFYHOST] = 2;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $params);
        $content = curl_exec($ch);
        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        Assertion::eq(1, preg_match('/^application\/json([\s|;].*)?$/', $content_type), sprintf('Content type is not "application/json". It is "%s".', $content_type));
        curl_close($ch);

        Assertion::notEmpty($content, 'Unable to get content.');
        $content = json_decode($content, true);
        Assertion::isArray($content, 'Invalid content.');

        return $content;
    }
}
