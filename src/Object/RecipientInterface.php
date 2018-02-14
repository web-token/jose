<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Interface RecipientInterface.
 */
interface RecipientInterface
{
    /**
     * @param array       $headers
     * @param string|null $encrypted_key
     *
     * @return \Jose\Object\Recipient
     */
    public static function createRecipientFromLoadedJWE(array $headers, $encrypted_key);

    /**
     * @param \Jose\Object\JWKInterface $recipient_key
     * @param array                     $headers
     *
     * @return \Jose\Object\Recipient
     */
    public static function createRecipient(JWKInterface $recipient_key, array $headers = []);

    /**
     * @return array
     */
    public function getHeaders();

    /**
     * Returns the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getHeader($key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasHeader($key);

    /**
     * @return string
     */
    public function getEncryptedKey();

    /**
     * @return \Jose\Object\JWKInterface
     */
    public function getRecipientKey();
}
