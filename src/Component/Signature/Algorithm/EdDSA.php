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

namespace Jose\Component\Signature\Algorithm;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\SignatureAlgorithmInterface;

/**
 * Class Ed25519.
 */
final class EdDSA implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The key is not private');

        $secret = Base64Url::decode($key->get('d'));
        $public = Base64Url::decode($key->get('x'));

        switch ($key->get('crv')) {
            case 'Ed25519':
                return ed25519_sign($input, $secret, $public);
            default:
                throw new \InvalidArgumentException('Unsupported curve');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);

        $public = Base64Url::decode($key->get('x'));

        switch ($key->get('crv')) {
            case 'Ed25519':
                return ed25519_sign_open($input, $public, $signature);
            default:
                throw new \InvalidArgumentException('Unsupported curve');
        }
    }

    /**
     * @param JWK $key
     */
    private function checkKey(JWK $key)
    {
        Assertion::eq($key->get('kty'), 'OKP', 'Wrong key type.');
        Assertion::true($key->has('x'), 'The key parameter "x" is missing.');
        Assertion::true($key->has('crv'), 'The key parameter "crv" is missing.');
        Assertion::inArray($key->get('crv'), ['Ed25519'], 'Unsupported curve');
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'EdDSA';
    }
}
