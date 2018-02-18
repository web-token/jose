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

use Assert\Assertion;

final class JWTCreator implements JWTCreatorInterface
{
    /**
     * @var \Jose\EncrypterInterface|null
     */
    private $encrypter = null;

    /**
     * @var \Jose\SignerInterface
     */
    private $signer;

    /**
     * JWTCreator constructor.
     *
     * @param \Jose\SignerInterface $signer
     */
    public function __construct(SignerInterface $signer)
    {
        $this->signer = $signer;
    }

    /**
     * @param \Jose\EncrypterInterface $encrypter
     */
    public function enableEncryptionSupport(EncrypterInterface $encrypter)
    {
        $this->encrypter = $encrypter;
    }

    /**
     * {@inheritdoc}
     */
    public function sign($payload, array $signature_protected_headers, Object\JWKInterface $signature_key)
    {
        $jws = Factory\JWSFactory::createJWS($payload);

        $jws = $jws->addSignatureInformation($signature_key, $signature_protected_headers);
        $this->signer->sign($jws);

        return $jws->toCompactJSON(0);
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function signAndEncrypt($payload, array $signature_protected_headers, Object\JWKInterface $signature_key, array $encryption_protected_headers, Object\JWKInterface $encryption_key)
    {
        $jws = $this->sign($payload, $signature_protected_headers, $signature_key);
        $jwe = $this->encrypt($jws, $encryption_protected_headers, $encryption_key);

        return $jwe;
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return false === $this->isEncryptionSupportEnabled() ? [] : $this->encrypter->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
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
