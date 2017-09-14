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

namespace Jose\Component\Signature;

use Jose\Component\Core\Converter\JsonConverterInterface;
use Jose\Component\Core\JWAManagerFactory;

final class JWSBuilderFactory
{
    /**
     * @var JsonConverterInterface
     */
    private $jsonEncoder;

    /**
     * @var JWAManagerFactory
     */
    private $signatureAlgorithmManagerFactory;

    /**
     * JWSBuilderFactory constructor.
     *
     * @param JsonConverterInterface $jsonEncoder
     * @param JWAManagerFactory       $signatureAlgorithmManagerFactory
     */
    public function __construct(JsonConverterInterface $jsonEncoder, JWAManagerFactory $signatureAlgorithmManagerFactory)
    {
        $this->jsonEncoder = $jsonEncoder;
        $this->signatureAlgorithmManagerFactory = $signatureAlgorithmManagerFactory;
    }

    /**
     * @param string[] $algorithms
     *
     * @return JWSBuilder
     */
    public function create(array $algorithms): JWSBuilder
    {
        $algorithmManager = $this->signatureAlgorithmManagerFactory->create($algorithms);

        return new JWSBuilder($this->jsonEncoder, $algorithmManager);
    }
}
