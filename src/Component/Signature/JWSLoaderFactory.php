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

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\JWAManagerFactory;

final class JWSLoaderFactory
{
    /**
     * @var JWAManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    /**
     * JWSLoaderFactory constructor.
     *
     * @param JWAManagerFactory           $algorithmManagerFactory
     * @param HeaderCheckerManagerFactory $headerCheckerManagerFactory
     */
    public function __construct(JWAManagerFactory $algorithmManagerFactory, HeaderCheckerManagerFactory $headerCheckerManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    /**
     * @param string[] $algorithms
     * @param string[] $headerCheckers
     *
     * @return JWSLoader
     */
    public function create(array $algorithms, array $headerCheckers): JWSLoader
    {
        $algorithmManager = $this->algorithmManagerFactory->create($algorithms);
        $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);

        return new JWSLoader($algorithmManager, $headerCheckerManager);
    }
}
