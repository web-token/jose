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

use Jose\Component\Core\JWAManagerFactory;

final class JWSBuilderFactory
{
    /**
     * @var JWAManagerFactory
     */
    private $signatureAlgorithmManagerFactory;

    /**
     * JWSBuilderFactory constructor.
     *
     * @param JWAManagerFactory $signatureAlgorithmManagerFactory
     */
    public function __construct(JWAManagerFactory $signatureAlgorithmManagerFactory)
    {
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

        return new JWSBuilder($algorithmManager);
    }
}
