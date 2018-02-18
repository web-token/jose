<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
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
final class Signature implements SignatureInterface
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
     * {@inheritdoc}
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
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function getProtectedHeaders()
    {
        return $this->protected_headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncodedProtectedHeaders()
    {
        return $this->encoded_protected_headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getProtectedHeader($key)
    {
        if ($this->hasProtectedHeader($key)) {
            return $this->getProtectedHeaders()[$key];
        }

        throw new \InvalidArgumentException(sprintf('The protected header "%s" does not exist', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasProtectedHeader($key)
    {
        return array_key_exists($key, $this->getProtectedHeaders());
    }

    /**
     * {@inheritdoc}
     */
    public function getHeader($key)
    {
        if ($this->hasHeader($key)) {
            return $this->headers[$key];
        }

        throw new \InvalidArgumentException(sprintf('The header "%s" does not exist', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasHeader($key)
    {
        return array_key_exists($key, $this->headers);
    }

    public function getAllHeaders()
    {
        return array_merge(
            $this->getProtectedHeaders(),
            $this->getHeaders()
        );
    }

    /**
     * {@inheritdoc}
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
