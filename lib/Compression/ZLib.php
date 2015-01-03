<?php

namespace SpomkyLabs\JOSE\Compression;

use Jose\Compression\CompressionInterface;

/**
 * This class implements the compression algorithm ZLIB (ZLib).
 * This compression algorithm is not part of the specification.
 */
class ZLib implements CompressionInterface
{
    protected $compression_level = -1;

    /**
     * @param integer $level
     */
    public function setCompressionLevel($level)
    {
        if (!is_numeric($level) || $level < -1 || $level > 9) {
            throw new \InvalidArgumentException("The level of compression can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.");
        }

        return $this;
    }

    public function getCompressionLevel()
    {
        return $this->compression_level;
    }

    public function isMethodSupported($method)
    {
        return 'ZLIB' === $method;
    }

    public function compress($data)
    {
        return gzcompress($data, $this->getCompressionLevel());
    }

    public function uncompress($data)
    {
        return gzuncompress($data);
    }
}
