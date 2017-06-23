<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Service;

use Jose\Checker\CheckerManagerInterface;
use Jose\Decrypter;
use Jose\DecrypterInterface;
use Jose\Encrypter;
use Jose\EncrypterInterface;
use Jose\Factory\CheckerManagerFactory;
use Jose\JWTCreator;
use Jose\JWTLoader;
use Jose\Signer;
use Jose\SignerInterface;
use Jose\Verifier;
use Jose\VerifierInterface;

final class ServiceFactory
{
    /**
     * @var \SpomkyLabs\JoseBundle\Service\AlgorithmManager
     */
    private $algorithm_manager;

    /**
     * @var \SpomkyLabs\JoseBundle\Service\CompressionManager
     */
    private $compression_manager;

    /**
     * @var \SpomkyLabs\JoseBundle\Service\CheckerManager
     */
    private $checker_manager;

    /**
     * ServiceFactory constructor.
     *
     * @param \SpomkyLabs\JoseBundle\Service\AlgorithmManager   $algorithm_manager
     * @param \SpomkyLabs\JoseBundle\Service\CompressionManager $compression_manager
     * @param \SpomkyLabs\JoseBundle\Service\CheckerManager     $checker_manager
     */
    public function __construct(AlgorithmManager $algorithm_manager, CompressionManager $compression_manager, CheckerManager $checker_manager)
    {
        $this->algorithm_manager = $algorithm_manager;
        $this->compression_manager = $compression_manager;
        $this->checker_manager = $checker_manager;
    }

    /**
     * @param string[] $selected_key_encryption_algorithms
     * @param string[] $selected_content_encryption_algorithms
     * @param string[] $selected_compression_methods
     *
     * @return \Jose\EncrypterInterface
     */
    public function createEncrypter(array $selected_key_encryption_algorithms, array $selected_content_encryption_algorithms, array $selected_compression_methods)
    {
        $key_encryption_algorithms = $this->algorithm_manager->getSelectedAlgorithmMethods($selected_key_encryption_algorithms);
        $content_encryption_algorithms = $this->algorithm_manager->getSelectedAlgorithmMethods($selected_content_encryption_algorithms);
        $compression_methods = $this->compression_manager->getSelectedCompressionMethods($selected_compression_methods);

        return Encrypter::createEncrypter($key_encryption_algorithms, $content_encryption_algorithms, $compression_methods);
    }

    /**
     * @param string[] $selected_key_encryption_algorithms
     * @param string[] $selected_content_encryption_algorithms
     * @param string[] $selected_compression_methods
     *
     * @return \Jose\DecrypterInterface
     */
    public function createDecrypter(array $selected_key_encryption_algorithms, array $selected_content_encryption_algorithms, array $selected_compression_methods)
    {
        $key_encryption_algorithms = $this->algorithm_manager->getSelectedAlgorithmMethods($selected_key_encryption_algorithms);
        $content_encryption_algorithms = $this->algorithm_manager->getSelectedAlgorithmMethods($selected_content_encryption_algorithms);
        $compression_methods = $this->compression_manager->getSelectedCompressionMethods($selected_compression_methods);

        return Decrypter::createDecrypter($key_encryption_algorithms, $content_encryption_algorithms, $compression_methods);
    }

    /**
     * @param string[] $selected_algorithms
     *
     * @return \Jose\SignerInterface
     */
    public function createSigner(array $selected_algorithms)
    {
        $algorithms = $this->algorithm_manager->getSelectedAlgorithmMethods($selected_algorithms);

        return Signer::createSigner($algorithms);
    }

    /**
     * @param string[] $selected_algorithms
     *
     * @return \Jose\VerifierInterface
     */
    public function createVerifier(array $selected_algorithms)
    {
        $algorithms = $this->algorithm_manager->getSelectedAlgorithmMethods($selected_algorithms);

        return Verifier::createVerifier($algorithms);
    }

    /**
     * @param string[] $selected_claim_checkers
     * @param string[] $selected_header_checkers
     *
     * @return \Jose\Checker\CheckerManagerInterface
     */
    public function createChecker(array $selected_claim_checkers, array $selected_header_checkers)
    {
        $claim_checkers = $this->checker_manager->getSelectedClaimChecker($selected_claim_checkers);
        $header_checkers = $this->checker_manager->getSelectedHeaderChecker($selected_header_checkers);

        return CheckerManagerFactory::createClaimCheckerManager($claim_checkers, $header_checkers);
    }

    /**
     * @param \Jose\Checker\CheckerManagerInterface $checker_manager
     * @param \Jose\VerifierInterface               $verifier
     * @param \Jose\DecrypterInterface|null         $decrypter
     *
     * @return \Jose\JWTLoader
     */
    public function createJWTLoader(CheckerManagerInterface $checker_manager, VerifierInterface $verifier, DecrypterInterface $decrypter = null)
    {
        $jwt_loader = new JWTLoader($checker_manager, $verifier);
        if (null !== $decrypter) {
            $jwt_loader->enableDecryptionSupport($decrypter);
        }

        return $jwt_loader;
    }

    /**
     * @param \Jose\SignerInterface         $signer
     * @param \Jose\EncrypterInterface|null $encrypter
     *
     * @return \Jose\JWTCreator
     */
    public function createJWTCreator(SignerInterface $signer, EncrypterInterface $encrypter = null)
    {
        $jwt_creator = new JWTCreator($signer);
        if (null !== $encrypter) {
            $jwt_creator->enableEncryptionSupport($encrypter);
        }

        return $jwt_creator;
    }
}
