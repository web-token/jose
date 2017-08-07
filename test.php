<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

include_once 'vendor/autoload.php';

var_dump(\Jose\Component\KeyManagement\JWKFactory::createOctKey(['size' => 192])->all());
