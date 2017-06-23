<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Compression;

/**
 * Compression method manager.
 */
final class CompressionManager
{
    /**
     * @var CompressionInterface[]
     */
    private $compressionMethods = [];

    /**
     * @param CompressionInterface[] $methods
     *
     * @return CompressionManager
     */
    public static function create(array $methods): CompressionManager
    {
        $manager = new self();
        foreach ($methods as $method) {
            $manager->add($method);
        }

        return $manager;
    }

    /**
     * @param CompressionInterface $compressionMethod
     */
    public function add(CompressionInterface $compressionMethod)
    {
        $this->compressionMethods[$compressionMethod->name()] = $compressionMethod;
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->compressionMethods);
    }

    /**
     * This method will try to find a CompressionInterface object able to support the compression method.
     *
     * @param string $name The name of the compression method
     *
     * @return CompressionInterface
     */
    public function get(string $name): CompressionInterface
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException(sprintf('The compression method "%s" is not supported.', $name));
        }

        return $this->compressionMethods[$name];
    }

    /**
     * @return string[]
     */
    public function list(): array
    {
        return array_keys($this->compressionMethods);
    }
}
