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

final class JWTLoader implements JWTLoaderInterface
{
    /**
     * @var \Jose\LoaderInterface
     */
    private $loader;

    /**
     * @var \Jose\Checker\CheckerManagerInterface
     */
    private $checker_manager;

    /**
     * @var \Jose\DecrypterInterface|null
     */
    private $decrypter = null;

    /**
     * @var \Jose\VerifierInterface
     */
    private $verifier;

    /**
     * JWTLoader constructor.
     *
     * @param \Jose\Checker\CheckerManagerInterface $checker_manager
     * @param \Jose\VerifierInterface               $verifier
     */
    public function __construct(Checker\CheckerManagerInterface $checker_manager, VerifierInterface $verifier)
    {
        $this->checker_manager = $checker_manager;
        $this->verifier = $verifier;
        $this->loader = new Loader();
    }

    /**
     * {@inheritdoc}
     */
    public function enableDecryptionSupport(DecrypterInterface $decrypter)
    {
        $this->decrypter = $decrypter;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedSignatureAlgorithms()
    {
        return $this->verifier->getSupportedSignatureAlgorithms();
    }

    /**
     * @return bool
     */
    public function isDecryptionSupportEnabled()
    {
        return null !== $this->decrypter;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedCompressionMethods()
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedCompressionMethods();
    }

    /**
     * {@inheritdoc}
     */
    public function load($assertion, Object\JWKSetInterface $encryption_key_set = null, $is_encryption_required = false)
    {
        Assertion::string($assertion);
        Assertion::boolean($is_encryption_required);
        $jwt = $this->loader->load($assertion);
        if ($jwt instanceof Object\JWEInterface) {
            Assertion::notNull($encryption_key_set, 'Encryption key set is not available.');
            Assertion::true($this->isDecryptionSupportEnabled(), 'Encryption support is not enabled.');
            Assertion::inArray($jwt->getSharedProtectedHeader('alg'), $this->getSupportedKeyEncryptionAlgorithms(), sprintf('The key encryption algorithm "%s" is not allowed.', $jwt->getSharedProtectedHeader('alg')));
            Assertion::inArray($jwt->getSharedProtectedHeader('enc'), $this->getSupportedContentEncryptionAlgorithms(), sprintf('The content encryption algorithm "%s" is not allowed or not supported.', $jwt->getSharedProtectedHeader('enc')));
            $jwt = $this->decryptAssertion($jwt, $encryption_key_set);
        } elseif (true === $is_encryption_required) {
            throw new \InvalidArgumentException('The assertion must be encrypted.');
        }

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(Object\JWSInterface $jws, Object\JWKSetInterface $signature_key_set, $detached_payload = null)
    {
        Assertion::inArray($jws->getSignature(0)->getProtectedHeader('alg'), $this->getSupportedSignatureAlgorithms(), sprintf('The signature algorithm "%s" is not supported or not allowed.', $jws->getSignature(0)->getProtectedHeader('alg')));

        $index = null;
        $this->verifier->verifyWithKeySet($jws, $signature_key_set, $detached_payload, $index);
        Assertion::notNull($index, 'JWS signature(s) verification failed.');
        $this->checker_manager->checkJWS($jws, $index);

        return $index;
    }

    /**
     * @param \Jose\Object\JWEInterface    $jwe
     * @param \Jose\Object\JWKSetInterface $encryption_key_set
     *
     * @return \Jose\Object\JWSInterface
     */
    private function decryptAssertion(Object\JWEInterface $jwe, Object\JWKSetInterface $encryption_key_set)
    {
        $this->decrypter->decryptUsingKeySet($jwe, $encryption_key_set);

        $jws = $this->loader->load($jwe->getPayload());
        Assertion::isInstanceOf($jws, Object\JWSInterface::class, 'The encrypted assertion does not contain a JWS.');

        return $jws;
    }
}
