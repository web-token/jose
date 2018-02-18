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

interface JWTLoaderInterface
{
    /**
     * @param \Jose\DecrypterInterface $decrypter
     */
    public function enableDecryptionSupport(DecrypterInterface $decrypter);

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms();

    /**
     * @return bool
     */
    public function isDecryptionSupportEnabled();

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
     * @param string                            $assertion
     * @param \Jose\Object\JWKSetInterface|null $encryption_key_set
     * @param bool                              $is_encryption_required
     *
     * @return \Jose\Object\JWSInterface
     */
    public function load($assertion, Object\JWKSetInterface $encryption_key_set = null, $is_encryption_required = false);

    /**
     * @param \Jose\Object\JWSInterface    $jws
     * @param \Jose\Object\JWKSetInterface $signature_key_set
     * @param string|null                  $detached_payload
     *
     * @return int
     */
    public function verify(Object\JWSInterface $jws, Object\JWKSetInterface $signature_key_set, $detached_payload = null);
}
