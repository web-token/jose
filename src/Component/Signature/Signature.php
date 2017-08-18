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

namespace Jose\Component\Signature;

use Base64Url\Base64Url;

final class Signature
{
    /**
     * @var null|string
     */
    private $encodedProtectedHeaders = null;

    /**
     * @var array
     */
    private $protectedHeaders = [];

    /**
     * @var array
     */
    private $headers = [];

    /**
     * @var string
     */
    private $signature;

    /**
     * Signature constructor.
     *
     * @param string      $signature
     * @param null|string $encodedProtectedHeaders
     * @param array       $headers
     */
    private function __construct(string $signature, ?string $encodedProtectedHeaders, array $headers)
    {
        if (null !== $encodedProtectedHeaders) {
            $protected_headers = json_decode(Base64Url::decode($encodedProtectedHeaders), true);
            if (!is_array($protected_headers)) {
                throw new \InvalidArgumentException('Unable to decode the protected headers.');
            }
            $this->protectedHeaders = $protected_headers;
        }
        $this->encodedProtectedHeaders = $encodedProtectedHeaders;
        $this->signature = $signature;
        $this->headers = $headers;
    }

    /**
     * @param string      $signature
     * @param string|null $encodedProtectedHeaders
     * @param array       $headers
     *
     * @return Signature
     */
    public static function create(string $signature, ?string $encodedProtectedHeaders, array $headers = []): Signature
    {
        return new self($signature, $encodedProtectedHeaders, $headers);
    }

    /**
     * The protected header associated with the signature.
     *
     * @return array
     */
    public function getProtectedHeaders(): array
    {
        return $this->protectedHeaders;
    }

    /**
     * The unprotected header associated with the signature.
     *
     * @return array
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * The protected header associated with the signature.
     *
     *
     * @return null|string
     */
    public function getEncodedProtectedHeaders(): ?string
    {
        return $this->encodedProtectedHeaders;
    }

    /**
     * Returns the value of the protected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getProtectedHeader(string $key)
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
    public function hasProtectedHeader(string $key): bool
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
    public function getHeader(string $key)
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
    public function hasHeader(string $key): bool
    {
        return array_key_exists($key, $this->headers);
    }

    /**
     * Returns the value of the signature.
     *
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }
}
