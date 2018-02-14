<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Compression\CompressionInterface;

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
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return $this->key_encryption_algorithms;
    }

    /**
     * @param string[]|\Jose\Algorithm\KeyEncryptionAlgorithmInterface[] $key_encryption_algorithms
     */
    private function setKeyEncryptionAlgorithms($key_encryption_algorithms)
    {
        $result = [];
        foreach ($key_encryption_algorithms as $key_encryption_algorithm) {
            if (is_string($key_encryption_algorithm)) {
                $result[] = $key_encryption_algorithm;
            } elseif ($key_encryption_algorithm instanceof KeyEncryptionAlgorithmInterface) {
                $result[] = $key_encryption_algorithm->getAlgorithmName();
            } else {
                throw new \InvalidArgumentException('Parameter must be a string or an instance of KeyEncryptionAlgorithmInterface');
            }
        }
        $this->key_encryption_algorithms = $result;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return $this->content_encryption_algorithms;
    }

    /**
     * @param string[]|\Jose\Algorithm\ContentEncryptionAlgorithmInterface[] $content_encryption_algorithms
     */
    private function setContentEncryptionAlgorithms($content_encryption_algorithms)
    {
        $result = [];
        foreach ($content_encryption_algorithms as $content_encryption_algorithm) {
            if (is_string($content_encryption_algorithm)) {
                $result[] = $content_encryption_algorithm;
            } elseif ($content_encryption_algorithm instanceof ContentEncryptionAlgorithmInterface) {
                $result[] = $content_encryption_algorithm->getAlgorithmName();
            } else {
                throw new \InvalidArgumentException('Parameter must be a string or an instance of KeyEncryptionAlgorithmInterface');
            }
        }
        $this->content_encryption_algorithms = $result;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedCompressionMethods()
    {
        return $this->compression_methods;
    }

    /**
     * @param string[]|\Jose\Compression\CompressionInterface[] $compression_methods
     */
    private function setCompressionMethods($compression_methods)
    {
        $result = [];
        foreach ($compression_methods as $compression_method) {
            if (is_string($compression_method)) {
                $result[] = $compression_method;
            } elseif ($compression_method instanceof CompressionInterface) {
                $result[] = $compression_method->getMethodName();
            } else {
                throw new \InvalidArgumentException('Parameter must be a string or an instance of CompressionInterface');
            }
        }
        $this->compression_methods = $result;
    }
}
