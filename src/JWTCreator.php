<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Assert\Assertion;
use Jose\Component\Encryption\Encrypter;
use Jose\Component\Signature\Signer;
use Jose\Component\Core\JWKInterface;

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
    public function sign($payload, array $signature_protected_headers, JWKInterface $signature_key): string
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
    public function encrypt(string $payload, array $encryption_protected_headers, JWKInterface $encryption_key): string
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
    public function signAndEncrypt($payload, array $signature_protected_headers, JWKInterface $signature_key, array $encryption_protected_headers, JWKInterface $encryption_key): string
    {
        $jws = $this->sign($payload, $signature_protected_headers, $signature_key);
        $jwe = $this->encrypt($jws, $encryption_protected_headers, $encryption_key);

        return $jwe;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms(): array
    {
        return $this->signer->getSupportedSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms(): array
    {
        return false === $this->isEncryptionSupportEnabled() ? [] : $this->encrypter->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms(): array
    {
        return false === $this->isEncryptionSupportEnabled() ? [] : $this->encrypter->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods(): array
    {
        return false === $this->isEncryptionSupportEnabled() ? [] : $this->encrypter->getSupportedCompressionMethods();
    }

    /**
     * @return bool
     */
    public function isEncryptionSupportEnabled(): bool
    {
        return null !== $this->encrypter;
    }
}
