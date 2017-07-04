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

namespace Jose\Component\Encryption\Compression;

use Assert\Assertion;

final class CompressionManagerFactory
{
    /**
     * @param string[]|CompressionInterface[] $methods
     *
     * @return CompressionManager
     */
    public static function createCompressionManager(array $methods): CompressionManager
    {
        $compression_manager = new CompressionManager();

        foreach ($methods as $method) {
            if ($method instanceof CompressionInterface) {
                $compression_manager->add($method);
            } else {
                Assertion::string($method, 'Bad argument: must be a list with either method names (string) or instances of CompressionInterface.');
                $class = self::getMethodClass($method);
                $compression_manager->add(new $class());
            }
        }

        return $compression_manager;
    }

    /**
     * @param string $method
     *
     * @return bool
     */
    private static function isAlgorithmSupported(string $method): bool
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
    private static function getMethodClass(string $method): string
    {
        Assertion::true(self::isAlgorithmSupported($method), sprintf('Compression method "%s" is not supported.', $method));

        return self::getSupportedMethods()[$method];
    }

    private static function getSupportedMethods(): array
    {
        return [
            'DEF' => '\Jose\Component\Encryption\Compression\Deflate',
            'GZ' => '\Jose\Component\Encryption\Compression\GZip',
            'ZLIB' => '\Jose\Component\Encryption\Compression\ZLib',
        ];
    }
}
