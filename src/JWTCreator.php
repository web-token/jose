<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Assert\Assertion;
use Jose\Object\JWKInterface;

final class JWTCreator
{
    /**
     * @var Encrypter|null
     */
    private $encrypter = null;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * JWTCreator constructor.
     *
     * @param Signer $signer
     */
    public function __construct(Signer $signer)
    {
        $this->signer = $signer;
    }

    /**
     * @param Encrypter $encrypter
     */
    public function enableEncryptionSupport(Encrypter $encrypter)
    {
        $this->encrypter = $encrypter;
    }

    /**
     * @param mixed                     $payload
     * @param array                     $signature_protected_headers
     * @param JWKInterface $signature_key
     *
     * @return string
     */
    public function sign($payload, array $signature_protected_headers, Object\JWKInterface $signature_key)
    {
        $jws = Factory\JWSFactory::createJWS($payload);

        $jws = $jws->addSignatureInformation($signature_key, $signature_protected_headers);
        $this->signer->sign($jws);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param string                    $payload
     * @param array                     $encryption_protected_headers
     * @param JWKInterface $encryption_key
     *
     * @return string
     */
    public function encrypt($payload, array $encryption_protected_headers, Object\JWKInterface $encryption_key)
    {
        Assertion::true($this->isEncryptionSupportEnabled(), 'The encryption support is not enabled');

        $jwe = Factory\JWEFactory::createJWE($payload, $encryption_protected_headers);
        $jwe = $jwe->addRecipientInformation($encryption_key);
        $this->encrypter->encrypt($jwe);

        return $jwe->toCompactJSON(0);
    }

    /**
     * @param mixed                     $payload
     * @param array                     $signature_protected_headers
     * @param JWKInterface $signature_key
     * @param array                     $encryption_protected_headers
     * @param JWKInterface $encryption_key
     *
     * @return string
     */
    public function signAndEncrypt($payload, array $signature_protected_headers, Object\JWKInterface $signature_key, array $encryption_protected_headers, Object\JWKInterface $encryption_key)
    {
        $jws = $this->sign($payload, $signature_protected_headers, $signature_key);
        $jwe = $this->encrypt($jws, $encryption_protected_headers, $encryption_key);

        return $jwe;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms()
    {
        return $this->signer->getSupportedSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return false === $this->isEncryptionSupportEnabled() ? [] : $this->encrypter->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return false === $this->isEncryptionSupportEnabled() ? [] : $this->encrypter->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods()
    {
        return false === $this->isEncryptionSupportEnabled() ? [] : $this->encrypter->getSupportedCompressionMethods();
    }

    /**
     * @return bool
     */
    public function isEncryptionSupportEnabled()
    {
        return null !== $this->encrypter;
    }
}
