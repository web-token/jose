<?php
include_once 'vendor/autoload.php';

var_dump(\Jose\Component\KeyManagement\JWKFactory::createOctKey(['size' => 192])->all());