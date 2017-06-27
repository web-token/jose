<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Routing;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Config\Loader\LoaderResolverInterface;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

final class JWKSetLoader implements LoaderInterface
{
    /**
     * @var \Symfony\Component\Routing\RouteCollection
     */
    private $routes;

    /**
     * JWKSetLoader Constructor.
     */
    public function __construct()
    {
        $this->routes = new RouteCollection();
    }

    /**
     * @param string $pattern
     * @param string $name
     */
    public function addJWKSetRoute($pattern, $name)
    {
        $controller_id = 'jose.controller.'.$name;

        $defaults = ['_controller' => $controller_id.':getAction', '_format' => 'json'];
        $requirements = ['_format' => 'json|pem'];
        $route = new Route($pattern.'.{_format}', $defaults, $requirements);
        $this->routes->add('jwkset_'.$name, $route);
    }

    /**
     * {@inheritdoc}
     */
    public function load($resource, $type = null)
    {
        return $this->routes;
    }

    /**
     * {@inheritdoc}
     */
    public function supports($resource, $type = null)
    {
        return 'jwkset' === $type;
    }

    /**
     * {@inheritdoc}
     */
    public function getResolver()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function setResolver(LoaderResolverInterface $resolver)
    {
    }
}
