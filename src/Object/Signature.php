<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

use Assert\Assertion;
use Base64Url\Base64Url;

/**
 * Class SignatureInstruction.
 */
final class Signature
{
    /**
     * @var null|string
     */
    private $encoded_protected_headers = null;

    /**
     * @var array
     */
    private $protected_headers = [];

    /**
     * @var array
     */
    private $headers = [];

    /**
     * @var string
     */
    private $signature;

    /**
     * @var \Jose\Object\JWKInterface
     */
    private $signature_key;

    /**
     * @param string      $signature
     * @param string|null $encoded_protected_headers
     * @param array       $headers
     *
     * @return \Jose\Object\Signature
     */
    public static function createSignatureFromLoadedData($signature, $encoded_protected_headers, array $headers)
    {
        $object = new self();
        $object->encoded_protected_headers = $encoded_protected_headers;
        if (null !== $encoded_protected_headers) {
            $protected_headers = json_decode(Base64Url::decode($encoded_protected_headers), true);
            Assertion::isArray($protected_headers, 'Unable to decode the protected headers.');
            $object->protected_headers = $protected_headers;
        }
        $object->signature = $signature;
        $object->headers = $headers;

        return $object;
    }

    /**
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return \Jose\Object\Signature
     */
    public static function createSignature(JWKInterface $signature_key, array $protected_headers, array $headers)
    {
        $object = new self();
        $object->protected_headers = $protected_headers;
        if (!empty($protected_headers)) {
            $object->encoded_protected_headers = Base64Url::encode(json_encode($protected_headers));
        }
        $object->signature_key = $signature_key;
        $object->headers = $headers;

        return $object;
    }

    /**
     * The protected header associated with the signature.
     *
     * @return array
     */
    public function getProtectedHeaders()
    {
        return $this->protected_headers;
    }

    /**
     * The unprotected header associated with the signature.
     *
     * @return array
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * The protected header associated with the signature.
     *
     *
     * @return null|string
     */
    public function getEncodedProtectedHeaders()
    {
        return $this->encoded_protected_headers;
    }

    /**
     * Returns the value of the protected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getProtectedHeader($key)
    {
        if ($this->hasProtectedHeader($key)) {
            return $this->getProtectedHeaders()[$key];
        }
        throw new \InvalidArgumentException(sprintf('The protected header "%s" does not exist', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasProtectedHeader($key)
    {
        return array_key_exists($key, $this->getProtectedHeaders());
    }

    /**
     * Returns the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getHeader($key)
    {
        if ($this->hasHeader($key)) {
            return $this->headers[$key];
        }
        throw new \InvalidArgumentException(sprintf('The header "%s" does not exist', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasHeader($key)
    {
        return array_key_exists($key, $this->headers);
    }

    /**
     * The protected and unprotected header associated with the signature.
     *
     * @return array
     */
    public function getAllHeaders()
    {
        return array_merge(
            $this->getProtectedHeaders(),
            $this->getHeaders()
        );
    }

    /**
     * Returns the value of the signature.
     *
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    public function getSignatureKey()
    {
        return $this->signature_key;
    }
}
