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

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Compression\CompressionMethodManager;

final class JWELoader
{
    /**
     * @var HeaderCheckerManager
     */
    private $headerCheckerManager;

    /**
     * @var Decrypter
     */
    private $decrypter;

    /**
     * JWELoader constructor.
     *
     * @param JWAManager $keyEncryptionAlgorithmManager
     * @param JWAManager $contentEncryptionAlgorithmManager
     * @param CompressionMethodManager $compressionMethodManager
     * @param HeaderCheckerManager $headerCheckerManager
     */
    public function __construct(JWAManager $keyEncryptionAlgorithmManager, JWAManager $contentEncryptionAlgorithmManager, CompressionMethodManager $compressionMethodManager, HeaderCheckerManager $headerCheckerManager)
    {
        $this->decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager);
        $this->headerCheckerManager = $headerCheckerManager;
    }

    /**
     * @param string $input
     * @param JWKSet $keyset
     *
     * @return JWE
     */
    public function load(string $input, JWKSet $keyset): JWE
    {
        $jwe = JWEParser::parse($input);
        $index = null;
        $jwe = $this->decrypter->decryptUsingKeySet($jwe, $keyset, $index);
        $this->headerCheckerManager->checkJWE($jwe, $index);

        return $jwe;
    }
}
