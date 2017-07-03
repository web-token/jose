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

use Assert\Assertion;

/**
 * Behat context class.
 */
trait ResponseContext
{
    /**
     * @param string|null $name name of the session OR active session will be used
     *
     * @return \Behat\Mink\Session
     */
    abstract public function getSession($name = null);

    /**
     * @Then the response content-type should be :content_type
     */
    public function theResponseContentTypeShouldBe($content_type)
    {
        $header = $this->getSession()->getResponseHeaders();

        Assertion::keyExists($header, 'content-type', 'The response header has no content-type.');
        Assertion::inArray($content_type, $header['content-type'], sprintf('The response header content-type does not contain "%s".', $content_type));
    }

    /**
     * @Then the response should contain a key set in JWKSet format
     */
    public function theResponseShouldContainAKeySetInJwksetFormat()
    {
        $content = $this->getJsonContent();
        Assertion::keyExists($content, 'keys', 'The response does not contain a key set.');
        Assertion::isArray($content['keys'], 'The response does not contain a valid key set.');
    }

    /**
     * @Then the response should contain a key set in PEM format
     */
    public function theResponseShouldContainAKeySetInPemFormat()
    {
        $content = $this->getJsonContent();
        Assertion::allString($content, 'The response does not contain a valid key set with key in PEM format.');
    }

    /**
     * @return array
     */
    private function getJsonContent()
    {
        $content = json_decode($this->getSession()->getPage()->getContent(), true);

        Assertion::notNull($content, 'The response is not a JSON object.');
        Assertion::isArray($content, 'The response is not a JSON object.');

        return $content;
    }
}
