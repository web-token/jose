<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Compression\CompressionInterface;
use Jose\Compression\CompressionManager;
use Jose\Compression\Deflate;
use Jose\Compression\GZip;
use Jose\Compression\ZLib;

/**
 * Class CompressionTest.
 *
 * @group Unit
 */
class CompressionTest extends \PHPUnit_Framework_TestCase
{
    public function testGetValidCompressionAlgorithm()
    {
        $manager = new CompressionManager();
        $manager->addCompressionAlgorithm(new Deflate());
        $manager->addCompressionAlgorithm(new GZip());
        $manager->addCompressionAlgorithm(new ZLib());

        $compression = $manager->getCompressionAlgorithm('DEF');
        $this->assertInstanceOf(CompressionInterface::class, $compression);
    }

    public function testGetInvalidCompressionAlgorithm()
    {
        $manager = new CompressionManager();
        $manager->addCompressionAlgorithm(new Deflate());
        $manager->addCompressionAlgorithm(new GZip());
        $manager->addCompressionAlgorithm(new ZLib());

        $compression = $manager->getCompressionAlgorithm('FOO');
        $this->assertNull($compression);
    }

    public function testDeflate()
    {
        $compression = new Deflate(9);

        $data = 'Live long and Prosper.';
        $compressed = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        $this->assertNotNull($compressed);
        $this->assertSame($data, $uncompressed);
    }

    public function testGZip()
    {
        $compression = new GZip(9);

        $data = 'Live long and Prosper.';
        $compressed = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        $this->assertNotNull($compressed);
        $this->assertSame($data, $uncompressed);
    }

    public function testZLib()
    {
        $compression = new ZLib(9);

        $data = 'Live long and Prosper.';
        $compressed = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        $this->assertNotNull($compressed);
        $this->assertSame($data, $uncompressed);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testDeflateInvalidCompressionLevel()
    {
        new Deflate(100);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testGZipInvalidCompressionLevel()
    {
        new GZip(100);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testZLibInvalidCompressionLevel()
    {
        new ZLib(100);
    }
}
