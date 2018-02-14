<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Jose\Compression\CompressionInterface;
use Jose\Compression\CompressionManager;

final class CompressionManagerFactory
{
    /**
     * @param string[]|\Jose\Compression\CompressionInterface[] $methods
     *
     * @return \Jose\Compression\CompressionManagerInterface
     */
    public static function createCompressionManager(array $methods)
    {
        $compression_manager = new CompressionManager();

        foreach ($methods as $method) {
            if ($method instanceof CompressionInterface) {
                $compression_manager->addCompressionAlgorithm($method);
            } else {
                Assertion::string($method, 'Bad argument: must be a list with either method names (string) or instances of CompressionInterface.');
                $class = self::getMethodClass($method);
                $compression_manager->addCompressionAlgorithm(new $class());
            }
        }

        return $compression_manager;
    }

    /**
     * @param string $method
     *
     * @return bool
     */
    private static function isAlgorithmSupported($method)
    {
        return array_key_exists($method, self::getSupportedMethods());
    }

    /**
     * @param string $method
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getMethodClass($method)
    {
        Assertion::true(self::isAlgorithmSupported($method), sprintf('Compression method "%s" is not supported.', $method));

        return self::getSupportedMethods()[$method];
    }

    private static function getSupportedMethods()
    {
        return [
            'DEF' => '\Jose\Compression\Deflate',
            'GZ' => '\Jose\Compression\GZip',
            'ZLIB' => '\Jose\Compression\ZLib',
        ];
    }
}
