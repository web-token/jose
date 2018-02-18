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

/**
 * Encrypter Interface.
 */
interface EncrypterInterface
{
    /**
     * @param string[]|\Jose\Algorithm\KeyEncryptionAlgorithmInterface[]     $key_encryption_algorithms
     * @param string[]|\Jose\Algorithm\ContentEncryptionAlgorithmInterface[] $content_encryption_algorithms
     * @param string[]|\Jose\Compression\CompressionInterface[]              $compression_methods
     *
     * @return \Jose\EncrypterInterface
     */
    public static function createEncrypter(array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF', 'ZLIB', 'GZ']);

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
     * @param \Jose\Object\JWEInterface $jwe
     */
    public function encrypt(Object\JWEInterface &$jwe);
}
