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

namespace Jose\Component\Signature\Tests;

use Jose\Component\Core\JWAManagerFactory;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\JWSBuilderFactory;
use PHPUnit\Framework\TestCase;

abstract class AbstractSignatureTest extends TestCase
{
    /**
     * @var JWAManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @return JWAManagerFactory
     */
    protected function getAlgorithmManagerFactory(): JWAManagerFactory
    {
        if (null === $this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new JWAManagerFactory();
            $this->algorithmManagerFactory
                ->add('HS256', new Algorithm\HS256())
                ->add('HS384', new Algorithm\HS384())
                ->add('HS512', new Algorithm\HS512())
                ->add('ES256', new Algorithm\ES256())
                ->add('ES384', new Algorithm\ES384())
                ->add('ES512', new Algorithm\ES512())
                ->add('RS256', new Algorithm\RS256())
                ->add('RS384', new Algorithm\RS384())
                ->add('RS512', new Algorithm\RS512())
                ->add('PS256', new Algorithm\PS256())
                ->add('PS384', new Algorithm\PS384())
                ->add('PS512', new Algorithm\PS512())
                ->add('none', new Algorithm\None())
                ->add('EdDSA', new Algorithm\EdDSA());
        }

        return $this->algorithmManagerFactory;
    }

    /**
     * @var JWSBuilderFactory
     */
    private $jwsBuilderFactory;

    /**
     * @return JWSBuilderFactory
     */
    protected function getJWSBuilderFactory(): JWSBuilderFactory
    {
        if (null === $this->jwsBuilderFactory) {
            $this->jwsBuilderFactory = new JWSBuilderFactory(
                $this->getAlgorithmManagerFactory()
            );
        }

        return $this->jwsBuilderFactory;
    }
}
