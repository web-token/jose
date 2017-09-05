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

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\JWAManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;

final class JWELoaderFactory
{
    /**
     * @var JWAManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var CompressionMethodManagerFactory
     */
    private $compressionMethodManagerFactory;

    /**
     * @var HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    /**
     * JWELoaderFactory constructor.
     *
     * @param JWAManagerFactory               $algorithmManagerFactory
     * @param CompressionMethodManagerFactory $compressionMethodManagerFactory
     * @param HeaderCheckerManagerFactory     $headerCheckerManagerFactory
     */
    public function __construct(JWAManagerFactory $algorithmManagerFactory, CompressionMethodManagerFactory $compressionMethodManagerFactory, HeaderCheckerManagerFactory $headerCheckerManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    /**
     * @param string[] $keyEncryptionAlgorithms
     * @param string[] $contentEncryptionAlgorithms
     * @param string[] $compressionMethods
     * @param string[] $headerCheckers
     *
     * @return JWELoader
     */
    public function create(array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods, array $headerCheckers): JWELoader
    {
        $keyEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($keyEncryptionAlgorithms);
        $contentEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($contentEncryptionAlgorithms);
        $compressionMethodManager = $this->compressionMethodManagerFactory->create($compressionMethods);
        $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);

        return new JWELoader($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager, $headerCheckerManager);
    }
}
