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

use Jose\Object\JWSInterface;

/**
 * Behat context trait.
 */
trait JWTCreatorAndLoader
{
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
     * @Given I have a valid JWE created by :jwt_creator, signed using :signature_key and encrypted using :encryption_key stored in the variable :variable
     */
    public function iHaveAValidJweCreatedBySignedUsingAndEncryptedUsingStoredInTheVariable($jwt_creator, $signature_key, $encryption_key, $variable)
    {
        /*
         * @var \Jose\JWTCreator
         */
        $creator = $this->getContainer()->get($jwt_creator);

        /*
         * @var \Jose\Component\Core\JWK
         */
        $key1 = $this->getContainer()->get($signature_key);

        /*
         * @var \Jose\Component\Core\JWK
         */
        $key2 = $this->getContainer()->get($encryption_key);

        $jws = $creator->sign(
            $this->getPayload(),
            $this->signature_protected_header,
            $key1
        );

        $jwe = $creator->encrypt(
            $jws,
            $this->jwe_shared_protected_header,
            $key2
        );

        $this->$variable = $jwe;
    }

    /**
     * @When I want to load and verify the value in the variable :variable1 using the JWT Loader :jwt_loader and the decryption keyset :decryption_key and I store the result in the variable :variable2
     */
    public function iWantToLoadAndVerifyTheValueInTheVariableUsingTheJwtLoaderAndIStoreTheResultInTheVariable($variable1, $decryption_key, $jwt_loader, $variable2)
    {
        /*
         * @var \Jose\JWTLoader
         */
        $loader = $this->getContainer()->get($jwt_loader);

        /*
         * @var \Jose\Component\Core\JWKSet
         */
        $keyset = $this->getContainer()->get($decryption_key);

        $this->$variable2 = $loader->load($this->$variable1, $keyset, true);
    }

    /**
     * @Then the variable :variable should contain a JWS
     */
    public function theVariableShouldContainAJws($variable)
    {
        if (! $this->$variable instanceof JWSInterface) {
            throw new \Exception(sprintf('The variable "%s" does not contain a JWS object', $variable));
        }
    }
}
