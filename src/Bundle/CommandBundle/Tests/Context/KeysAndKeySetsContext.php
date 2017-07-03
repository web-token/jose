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
use Jose\Component\Core\JWKSet;

/**
 * Behat context trait.
 */
trait KeysAndKeySetsContext
{
    /**
     * Returns HttpKernel service container.
     *
     * @return \Symfony\Component\DependencyInjection\ContainerInterface
     */
    abstract protected function getContainer();

    /**
     * @param string $service
     * @param string $variable
     * @When I try to get the key :service and store it in the variable :variable
     * @When I try to get the keyset :service and store it in the variable :variable
     */
    public function iTryToGetTheKeyAndStoreItInTheVariable($service, $variable)
    {
        $this->$variable = $this->getContainer()->get($service);
    }

    /**
     * @param string $service
     * @param int    $number
     *
     * @throws \Exception
     *
     * @Then the keyset in the service :service contains :number key
     * @Then the keyset in the service :service contains :number keys
     */
    public function theKeysetInTheServiceContainsKeys($service, $number)
    {
        $this->theServiceShouldBeAnObjectThatImplements($service, JWKSet::class);
        if ((int) $number !== count($this->getContainer()->get($service))) {
            throw new \Exception(sprintf(
                'The service "%s" contains %d key(s).',
                $service,
                count($this->getContainer()->get($service))
            ));
        }
    }

    /**
     * @param string $service
     *
     * @throws \Exception
     *
     * @Then the keyset in the service :service contains keys
     */
    public function theKeysetInTheServiceContainsSomeKeys($service)
    {
        $this->theServiceShouldBeAnObjectThatImplements($service, JWKSet::class);
        if (0 === count($this->getContainer()->get($service))) {
            throw new \Exception(sprintf(
                'The service "%s" does not contain keys.',
                $service
            ));
        }
    }

    /**
     * @param string $service
     * @param string $interface
     *
     * @throws \Exception
     *
     * @Then the service :service should be an object that implements :interface
     */
    public function theServiceShouldBeAnObjectThatImplements($service, $interface)
    {
        if (! $this->getContainer()->get($service) instanceof $interface) {
            throw new \Exception(sprintf(
                'The service "%s" is not an instance of "%s". Its class is "%s".',
                $this->getContainer()->get($service),
                $interface,
                get_class($this->getContainer()->get($service))
            ));
        }
    }

    /**
     * @When I show JWKSet :id
     */
    public function iShowJWKSet($id)
    {
        $jwkset = $this->getContainer()->get($id);

        dump(json_encode($jwkset));
    }

    /**
     * @Then the route :route exists
     *
     * @param string $route_name
     */
    public function theRouteExists($route_name)
    {
        $router = $this->getContainer()->get('router');
        $route = $router->getRouteCollection()->get($route_name);

        Assertion::notNull($route, sprintf('The route with name "%s" does not exist.', $route_name));
    }
}
