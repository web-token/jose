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
use Jose\Object\JWKSetInterface;
use Jose\Object\JWS;

final class JWTLoader
{
    /**
     * @var Loader
     */
    private $loader;

    /**
     * @var Checker\CheckerManager
     */
    private $checker_manager;

    /**
     * @var Decrypter|null
     */
    private $decrypter = null;

    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * JWTLoader constructor.
     *
     * @param Checker\CheckerManager $checker_manager
     * @param Verifier               $verifier
     */
    public function __construct(Checker\CheckerManager $checker_manager, Verifier $verifier)
    {
        $this->checker_manager = $checker_manager;
        $this->verifier = $verifier;
        $this->loader = new Loader();
    }

    /**
     * @param Decrypter $decrypter
     */
    public function enableDecryptionSupport(Decrypter $decrypter)
    {
        $this->decrypter = $decrypter;
    }

    /**
     * @return string[]
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
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods()
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedCompressionMethods();
    }

    /**
     * @param string                            $assertion
     * @param JWKSetInterface|null $encryption_key_set
     * @param bool                              $is_encryption_required
     *
     * @return JWS
     */
    public function load($assertion, Object\JWKSetInterface $encryption_key_set = null, $is_encryption_required = false)
    {
        Assertion::string($assertion);
        Assertion::boolean($is_encryption_required);
        $jwt = $this->loader->load($assertion);
        if ($jwt instanceof Object\JWE) {
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
     * @param JWS    $jws
     * @param JWKSetInterface $signature_key_set
     * @param string|null                  $detached_payload
     *
     * @return int
     */
    public function verify(Object\JWS $jws, Object\JWKSetInterface $signature_key_set, $detached_payload = null)
    {
        Assertion::inArray($jws->getSignature(0)->getProtectedHeader('alg'), $this->getSupportedSignatureAlgorithms(), sprintf('The signature algorithm "%s" is not supported or not allowed.', $jws->getSignature(0)->getProtectedHeader('alg')));

        $index = null;
        $this->verifier->verifyWithKeySet($jws, $signature_key_set, $detached_payload, $index);
        Assertion::notNull($index, 'JWS signature(s) verification failed.');
        $this->checker_manager->checkJWS($jws, $index);

        return $index;
    }

    /**
     * @param Object\JWE    $jwe
     * @param Object\JWKSetInterface $encryption_key_set
     *
     * @return Object\JWS
     */
    private function decryptAssertion(Object\JWE $jwe, Object\JWKSetInterface $encryption_key_set)
    {
        $this->decrypter->decryptUsingKeySet($jwe, $encryption_key_set);

        $jws = $this->loader->load($jwe->getPayload());
        Assertion::isInstanceOf($jws, Object\JWS::class, 'The encrypted assertion does not contain a JWS.');

        return $jws;
    }
}
