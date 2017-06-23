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

use Assert\Assertion;
use Jose\Compression\CompressionInterface;

final class CompressionManager
{
    /**
     * @var \Jose\Compression\CompressionInterface[]
     */
    private $compression_methods = [];

    /**
     * @param \Jose\Compression\CompressionInterface $compression_method
     */
    public function addCompressionMethod(CompressionInterface $compression_method)
    {
        $name = $compression_method->getMethodName();
        if (!array_key_exists($name, $this->compression_methods)) {
            $this->compression_methods[$name] = $compression_method;
        }
    }

    /**
     * @param string[] $selected_compression_methods
     *
     * @return \Jose\Compression\CompressionInterface[]
     */
    public function getSelectedCompressionMethods(array $selected_compression_methods)
    {
        $result = [];
        foreach ($selected_compression_methods as $method) {
            Assertion::keyExists($this->compression_methods, $method, sprintf('The compression method "%s" is not supported.', $method));
            $result[] = $this->compression_methods[$method];
        }

        return $result;
    }
}
