<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Features\Context;

use Behat\Gherkin\Node\PyStringNode;

/**
 * Behat context trait.
 */
trait PayloadContext
{
    /**
     * @var mixed
     */
    private $payload;

    /**
     * @Given I have the following payload
     */
    public function iHaveTheFollowingPayload(PyStringNode $string)
    {
        $this->payload = $string->getRaw();
    }

    /**
     * @return mixed
     */
    protected function getPayload()
    {
        return $this->payload;
    }
}
