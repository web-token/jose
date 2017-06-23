<?php

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
trait JWECreationContext
{
    /**
     * @var array
     */
    private $recipient_header = [];

    /**
     * @var array
     */
    private $jwe_shared_protected_header = [];

    /**
     * @var array
     */
    private $jwe_shared_header = [];

    /**
     * @var array
     */
    private $jwe_aad = null;

    /**
     * Returns HttpKernel service container.
     *
     * @return \Symfony\Component\DependencyInjection\ContainerInterface
     */
    abstract protected function getContainer();

    /**
     * @return mixed
     */
    abstract protected function getPayload();

    /**
     * @Given I have the following values in the JWE shared protected header
     *
     * @param \Behat\Gherkin\Node\PyStringNode $string
     */
    public function iHaveTheFollowingValuesInTheJweSharedProtectedHeader(PyStringNode $string)
    {
        $this->jwe_shared_protected_header = json_decode($string->getRaw(), true);
    }

    /**
     * @Given I have the following values in the JWE shared header
     *
     * @param \Behat\Gherkin\Node\PyStringNode $string
     */
    public function iHaveTheFollowingValuesInTheJweSharedHeader(PyStringNode $string)
    {
        $this->jwe_shared_header = json_decode($string->getRaw(), true);
    }

    /**
     * @Given I have the following values in the recipient header
     *
     * @param \Behat\Gherkin\Node\PyStringNode $string
     */
    public function iHaveTheFollowingValuesInTheRecipientHeader(PyStringNode $string)
    {
        $this->recipient_header = json_decode($string->getRaw(), true);
    }

    /**
     * @Given I have the following value as AAD
     *
     * @param \Behat\Gherkin\Node\PyStringNode $string
     */
    public function iHaveTheFollowingValueAsAad(PyStringNode $string)
    {
        $this->jwe_aad = $string->getRaw();
    }

    /**
     * @When I try to create a JWE in JSON Compact Serialization Mode with recipient key :key_service and I store the result in the variable :variable
     *
     * @param string $key_service
     * @param string $variable
     */
    public function iTryToCreateAJweInJsonCompactSerializationModeWithRecipientKeyAndIStoreTheResultInTheVariable($key_service, $variable)
    {
        /*
         * @var \Jose\Factory\JWEFactory
         */
        $jwe_creator = $this->getContainer()->get('jose.factory.jwe');
        $key = $this->getContainer()->get($key_service);
        $this->$variable = $jwe_creator->createJWEToCompactJSON($this->getPayload(), $key, $this->jwe_shared_protected_header);
    }

    /**
     * @When I try to create a JWE in JSON Flattened Serialization Mode with recipient key :key_service and I store the result in the variable :variable
     *
     * @param string $key_service
     * @param string $variable
     */
    public function iTryToCreateAJweInJsonFlattenedSerializationModeWithRecipientKeyAndIStoreTheResultInTheVariable($key_service, $variable)
    {
        /*
         * @var \Jose\Factory\JWEFactory
         */
        $jwe_creator = $this->getContainer()->get('jose.factory.jwe');
        $key = $this->getContainer()->get($key_service);
        $this->$variable = $jwe_creator->createJWEToFlattenedJSON($this->getPayload(), $key, $this->jwe_shared_protected_header, $this->jwe_shared_header, $this->recipient_header, $this->jwe_aad);
    }
}
