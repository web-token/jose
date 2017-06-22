<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Compression\CompressionInterface;

trait CommonCipheringMethods
{
    /**
     * @var string[]
     */
    private $key_encryption_algorithms;

    /**
     * @var string[]
     */
    private $content_encryption_algorithms;

    /**
     * @var string[]
     */
    private $compression_methods;

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms(): array
    {
        return $this->key_encryption_algorithms;
    }

    /**
     * @param string[]|KeyEncryptionAlgorithmInterface[] $key_encryption_algorithms
     */
    private function setKeyEncryptionAlgorithms($key_encryption_algorithms)
    {
        $result = [];
        foreach ($key_encryption_algorithms as $key_encryption_algorithm) {
            if (is_string($key_encryption_algorithm)) {
                $result[] = $key_encryption_algorithm;
            } elseif ($key_encryption_algorithm instanceof KeyEncryptionAlgorithmInterface) {
                $result[] = $key_encryption_algorithm->name();
            } else {
                throw new \InvalidArgumentException('Parameter must be a string or an instance of KeyEncryptionAlgorithmInterface');
            }
        }
        $this->key_encryption_algorithms = $result;
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms(): array
    {
        return $this->content_encryption_algorithms;
    }

    /**
     * @param string[]|ContentEncryptionAlgorithmInterface[] $content_encryption_algorithms
     */
    private function setContentEncryptionAlgorithms($content_encryption_algorithms)
    {
        $result = [];
        foreach ($content_encryption_algorithms as $content_encryption_algorithm) {
            if (is_string($content_encryption_algorithm)) {
                $result[] = $content_encryption_algorithm;
            } elseif ($content_encryption_algorithm instanceof ContentEncryptionAlgorithmInterface) {
                $result[] = $content_encryption_algorithm->name();
            } else {
                throw new \InvalidArgumentException('Parameter must be a string or an instance of KeyEncryptionAlgorithmInterface');
            }
        }
        $this->content_encryption_algorithms = $result;
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods(): array
    {
        return $this->compression_methods;
    }

    /**
     * @param string[]|CompressionInterface[] $compression_methods
     */
    private function setCompressionMethods($compression_methods)
    {
        $result = [];
        foreach ($compression_methods as $compression_method) {
            if (is_string($compression_method)) {
                $result[] = $compression_method;
            } elseif ($compression_method instanceof CompressionInterface) {
                $result[] = $compression_method->name();
            } else {
                throw new \InvalidArgumentException('Parameter must be a string or an instance of CompressionInterface');
            }
        }
        $this->compression_methods = $result;
    }
}
