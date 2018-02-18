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

/**
 * Signature Instruction Interface.
 *
 * This interface is required by the SignerInterface to signed payloads and create a JWS.
 */
interface SignatureInterface
{
    /**
     * @param string      $signature
     * @param string|null $encoded_protected_headers
     * @param array       $headers
     *
     * @return \Jose\Object\Signature
     */
    public static function createSignatureFromLoadedData($signature, $encoded_protected_headers, array $headers);

    /**
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return \Jose\Object\Signature
     */
    public static function createSignature(JWKInterface $signature_key, array $protected_headers, array $headers);

    /**
     * @return \Jose\Object\JWKInterface
     */
    public function getSignatureKey();

    /**
     * The protected header associated with the signature.
     *
     * @internal
     *
     * @return null|string
     */
    public function getEncodedProtectedHeaders();

    /**
     * The protected header associated with the signature.
     *
     * @return array
     */
    public function getProtectedHeaders();

    /**
     * Returns the value of the protected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getProtectedHeader($key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasProtectedHeader($key);

    /**
     * The unprotected header associated with the signature.
     *
     * @return array
     */
    public function getHeaders();

    /**
     * Returns the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getHeader($key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasHeader($key);

    /**
     * The protected and unprotected header associated with the signature.
     *
     * @return array
     */
    public function getAllHeaders();

    /**
     * Returns the value of the signature.
     *
     * @return string
     */
    public function getSignature();
}
