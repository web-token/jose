<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Compression;

use Assert\Assertion;

/**
 * This class implements the compression algorithm DEF (defalte)
 * This compression algorithm is part of the specification.
 */
final class Deflate implements CompressionInterface
{
    /**
     * @var int
     */
    protected $compression_level = -1;

    /**
     * Deflate constructor.
     *
     * @param int $compression_level
     */
    public function __construct(int $compression_level = -1)
    {
        Assertion::integer($compression_level, 'The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.');
        Assertion::range($compression_level, -1, 9, 'The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.');

        $this->compression_level = $compression_level;
    }

    /**
     * @return int
     */
    private function getCompressionLevel(): int
    {
        return $this->compression_level;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'DEF';
    }

    /**
     * {@inheritdoc}
     */
    public function compress(string $data): string
    {
        $data = gzdeflate($data, $this->getCompressionLevel());
        Assertion::false(false === $data, 'Unable to compress data');

        return $data;
    }

    /**
     * {@inheritdoc}
     */
    public function uncompress(string $data): string
    {
        $data = gzinflate($data);
        Assertion::false(false === $data, 'Unable to uncompress data');

        return $data;
    }
}
