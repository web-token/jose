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

final class CompressionMethodsManagerFactory
{
    /**
     * @var CompressionInterface[]
     */
    private $compressionMethods = [];

    /**
     * @param string $alias
     * @param CompressionMethodsManager $compressionMethod
     */
    public function add(string $alias, CompressionMethodsManager $compressionMethod)
    {
        $this->compressionMethods[$alias] = $compressionMethod;
    }

    /**
     * @param string[] $aliases
     *
     * @return CompressionMethodsManager
     */
    public function create(array $aliases): CompressionMethodsManager
    {
        $compressionMethods = [];
        foreach ($aliases as $alias) {
            if (array_key_exists($alias, $this->compressionMethods)) {
                $compressionMethods[] = $this->compressionMethods[$alias];
            } else {
                throw new \InvalidArgumentException(sprintf('The compression method with the alias "%s" is not supported.', $alias));
            }
        }

        return CompressionMethodsManager::create($compressionMethods);
    }
}
