<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

interface JWTCreatorInterface
{
    /**
     * @param \Jose\EncrypterInterface $encrypter
     */
    public function enableEncryptionSupport(EncrypterInterface $encrypter);

    /**
     * @param mixed                     $payload
     * @param array                     $signature_protected_headers
     * @param \Jose\Object\JWKInterface $signature_key
     *
     * @return string
     */
    public function sign($payload, array $signature_protected_headers, Object\JWKInterface $signature_key);

    /**
     * @param string                    $payload
     * @param array                     $encryption_protected_headers
     * @param \Jose\Object\JWKInterface $encryption_key
     *
     * @return string
     */
    public function encrypt($payload, array $encryption_protected_headers, Object\JWKInterface $encryption_key);

    /**
     * @param mixed                     $payload
     * @param array                     $signature_protected_headers
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $encryption_protected_headers
     * @param \Jose\Object\JWKInterface $encryption_key
     *
     * @return string
     */
    public function signAndEncrypt($payload, array $signature_protected_headers, Object\JWKInterface $signature_key, array $encryption_protected_headers, Object\JWKInterface $encryption_key);

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms();

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms();

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms();

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods();

    /**
     * @return bool
     */
    public function isEncryptionSupportEnabled();
}
