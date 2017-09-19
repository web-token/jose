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

namespace Jose\Component\Encryption\Tests;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\Converter\StandardJsonConverter;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Compression;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWELoaderFactory;
use PHPUnit\Framework\TestCase;

abstract class AbstractEncryptionTest extends TestCase
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @return AlgorithmManagerFactory
     */
    protected function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (null === $this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory
                ->add('A128GCM', new ContentEncryption\A128GCM())
                ->add('A192GCM', new ContentEncryption\A192GCM())
                ->add('A256GCM', new ContentEncryption\A256GCM())
                ->add('A128CBC-HS256', new ContentEncryption\A128CBCHS256())
                ->add('A192CBC-HS384', new ContentEncryption\A192CBCHS384())
                ->add('A256CBC-HS512', new ContentEncryption\A256CBCHS512())
                ->add('A128GCMKW', new KeyEncryption\A128GCMKW())
                ->add('A192GCMKW', new KeyEncryption\A192GCMKW())
                ->add('A256GCMKW', new KeyEncryption\A256GCMKW())
                ->add('A128KW', new KeyEncryption\A128KW())
                ->add('A192KW', new KeyEncryption\A192KW())
                ->add('A256KW', new KeyEncryption\A256KW())
                ->add('dir', new KeyEncryption\Dir())
                ->add('ECDH-ES', new KeyEncryption\ECDHES())
                ->add('ECDH-ES+A128KW', new KeyEncryption\ECDHESA128KW())
                ->add('ECDH-ES+A192KW', new KeyEncryption\ECDHESA192KW())
                ->add('ECDH-ES+A256KW', new KeyEncryption\ECDHESA256KW())
                ->add('PBES2-HS256+A128KW', new KeyEncryption\PBES2HS256A128KW())
                ->add('PBES2-HS384+A192KW', new KeyEncryption\PBES2HS384A192KW())
                ->add('PBES2-HS512+A256KW', new KeyEncryption\PBES2HS512A256KW())
                ->add('RSA1_5', new KeyEncryption\RSA15())
                ->add('RSA-OAEP', new KeyEncryption\RSAOAEP())
                ->add('RSA-OAEP-256', new KeyEncryption\RSAOAEP256());
        }

        return $this->algorithmManagerFactory;
    }

    /**
     * @var CompressionMethodManagerFactory
     */
    private $compressionMethodManagerFactory;

    /**
     * @return CompressionMethodManagerFactory
     */
    protected function getCompressionMethodManagerFactory(): CompressionMethodManagerFactory
    {
        if (null === $this->compressionMethodManagerFactory) {
            $this->compressionMethodManagerFactory = new CompressionMethodManagerFactory();
            $this->compressionMethodManagerFactory
                ->add('DEF', new Compression\Deflate())
                ->add('ZLIB', new Compression\ZLib())
                ->add('GZ', new Compression\GZip());
        }

        return $this->compressionMethodManagerFactory;
    }

    /**
     * @var JWEBuilderFactory
     */
    private $jwsBuilderFactory;

    /**
     * @return JWEBuilderFactory
     */
    protected function getJWEBuilderFactory(): JWEBuilderFactory
    {
        if (null === $this->jwsBuilderFactory) {
            $this->jwsBuilderFactory = new JWEBuilderFactory(
                new StandardJsonConverter(),
                $this->getAlgorithmManagerFactory(),
                $this->getCompressionMethodManagerFactory()
            );
        }

        return $this->jwsBuilderFactory;
    }

    /**
     * @var JWELoaderFactory
     */
    private $jwsLoaderFactory;

    /**
     * @return JWELoaderFactory
     */
    protected function getJWELoaderFactory(): JWELoaderFactory
    {
        if (null === $this->jwsLoaderFactory) {
            $this->jwsLoaderFactory = new JWELoaderFactory(
                $this->getAlgorithmManagerFactory(),
                $this->getCompressionMethodManagerFactory(),
                $this->getHeaderCheckerManagerFactory()
            );
        }

        return $this->jwsLoaderFactory;
    }

    /**
     * @var HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    /**
     * @return HeaderCheckerManagerFactory
     */
    protected function getHeaderCheckerManagerFactory(): HeaderCheckerManagerFactory
    {
        if (null === $this->headerCheckerManagerFactory) {
            $this->headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
        }

        return $this->headerCheckerManagerFactory;
    }
}
