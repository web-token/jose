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

interface JWSInterface extends JWTInterface
{
    /**
     * @return bool
     */
    public function isPayloadDetached();

    /**
     * @return \Jose\Object\JWTInterface
     */
    public function withDetachedPayload();

    /**
     * @return \Jose\Object\JWTInterface
     */
    public function withAttachedPayload();

    /**
     * @param \Jose\Object\SignatureInterface $signature
     *
     * @internal
     *
     * @return string|null
     */
    public function getEncodedPayload(SignatureInterface $signature);

    /**
     * Returns the number of signature associated with the JWS.
     *
     * @internal
     *
     * @return int
     */
    public function countSignatures();

    /**
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return \Jose\Object\JWSInterface
     */
    public function addSignatureInformation(JWKInterface $signature_key, array $protected_headers, array $headers = []);

    /**
     * @param string      $signature
     * @param string|null $encoded_protected_headers
     * @param array       $headers
     *
     * @return \Jose\Object\JWSInterface
     */
    public function addSignatureFromLoadedData($signature, $encoded_protected_headers, array $headers);

    /**
     * Returns the signature associated with the JWS.
     *
     * @return \Jose\Object\SignatureInterface[]
     */
    public function getSignatures();

    /**
     * @param int $id
     *
     * @return \Jose\Object\SignatureInterface
     */
    public function &getSignature($id);

    /**
     * @param int $id
     *
     * @return string
     */
    public function toCompactJSON($id);

    /**
     * @param int $id
     *
     * @return string
     */
    public function toFlattenedJSON($id);

    /**
     * @return string
     */
    public function toJSON();
}
