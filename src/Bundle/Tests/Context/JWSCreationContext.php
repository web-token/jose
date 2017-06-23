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
trait JWSCreationContext
{
    /**
     * @var array
     */
    private $signature_protected_header = [];

    /**
     * @var array
     */
    private $signature_header = [];

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
     * @Given I have the following values in the signature protected header
     *
     * @param \Behat\Gherkin\Node\PyStringNode $string
     */
    public function iHaveTheFollowingValuesInTheSignatureProtectedHeader(PyStringNode $string)
    {
        $this->signature_protected_header = json_decode($string->getRaw(), true);
    }

    /**
     * @Given I have the following values in the signature header
     *
     * @param \Behat\Gherkin\Node\PyStringNode $string
     */
    public function iHaveTheFollowingValuesInTheSignatureHeader(PyStringNode $string)
    {
        $this->signature_header = json_decode($string->getRaw(), true);
    }

    /**
     * @When I try to create a JWS in JSON Compact Serialization Mode with signature key :key_service and I store the result in the variable :variable
     *
     * @param string $key_service
     * @param string $variable
     */
    public function iTryToCreateAJwsInJsonCompactSerializationModeWithSignatureKeyAndIStoreTheResultInTheVariable($key_service, $variable)
    {
        /*
         * @var \Jose\Factory\JWSFactory
         */
        $jws_creator = $this->getContainer()->get('jose.factory.jws');
        $key = $this->getContainer()->get($key_service);
        $this->$variable = $jws_creator->createJWSToCompactJSON($this->getPayload(), $key, $this->signature_protected_header);
    }

    /**
     * @When I try to create a JWS in JSON Flattened Serialization Mode with signature key :key_service and I store the result in the variable :variable
     *
     * @param string $key_service
     * @param string $variable
     */
    public function iTryToCreateAJwsInJsonFlattenedSerializationModeWithSignatureKeyAndIStoreTheResultInTheVariable($key_service, $variable)
    {
        /*
         * @var \Jose\Factory\JWSFactory
         */
        $jws_creator = $this->getContainer()->get('jose.factory.jws');
        $key = $this->getContainer()->get($key_service);
        $this->$variable = $jws_creator->createJWSToFlattenedJSON($this->getPayload(), $key, $this->signature_protected_header, $this->signature_header);
    }
}
