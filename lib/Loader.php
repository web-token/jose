<?php

namespace SpomkyLabs\Jose;

use SpomkyLabs\Jose\Util\Base64Url;
use Jose\JWAInterface;
use Jose\JWKInterface;
use Jose\JWKSetInterface;
use Jose\JWTManagerInterface;
use Jose\LoaderInterface;
use Jose\Operation\SignatureInterface;
use Jose\Operation\KeyAgreementInterface;
use Jose\Operation\KeyAgreementWrappingInterface;
use Jose\Operation\KeyEncryptionInterface;
use Jose\Operation\DirectEncryptionInterface;
use Jose\Operation\ContentEncryptionInterface;

/**
 * Class able to load JWS or JWT.
 */
abstract class Loader implements LoaderInterface
{
    /**
     * @return \Jose\JWKManagerInterface
     */
    abstract protected function getJWKManager();

    /**
     * @return \Jose\JWTManagerInterface
     */
    abstract protected function getJWTManager();

    /**
     * @return \Jose\JWAManagerInterface
     */
    abstract protected function getJWAManager();

    /**
     * @return \Jose\Compression\CompressionManagerInterface
     */
    abstract protected function getCompressionManager();

    /**
     * {@inheritdoc}
     */
    public function load($input, $verify_signature = true, JWKSetInterface $jwk_set = null)
    {
        //We try to identify if the data is a JSON object. In this case, we consider that data is a JSON (Flattened) Seralization object
        if (is_array($data = json_decode($input, true))) {
            return $this->loadSerializedJson($data, $verify_signature, $jwk_set);
        }

        //Else, we consider that data is a JSON Compact Seralized object
        return $this->loadCompactSerializedJson($input, $verify_signature, $jwk_set);
    }

    /**
     * {@inheritdoc}
     */
    public function verify($input, JWKSetInterface $jwk_set = null)
    {
    }

    /**
     * @param array $input
     */
    protected function loadSerializedJson($input, $verify_signature = true, JWKSetInterface $jwk_set = null)
    {
        if (array_key_exists("signatures", $input)) {
            return $this->loadSerializedJsonJWS($input, $verify_signature, $jwk_set);
        } elseif (array_key_exists("recipients", $input)) {
            return $this->loadSerializedJsonJWE($input, $jwk_set);
        } elseif (array_key_exists("signature", $input)) {
            $jws = array(
                "payload" => $input["payload"],
            );
            $signature = array();
            foreach (array("signature", "protected", "header") as $key) {
                if (array_key_exists($key, $input)) {
                    $signature[$key] = $input[$key];
                }
            }
            $jws["signatures"] = array($signature);

            return $this->loadSerializedJsonJWS($jws, $verify_signature, $jwk_set);
        } elseif (array_key_exists("encrypted_key", $input)) {
            $jwe = array(
                "encrypted_key" => $input["encrypted_key"],
            );
            foreach (array("ciphertext", "protected", "unprotected", "aad", "iv", "tag") as $key) {
                if (array_key_exists($key, $input)) {
                    $jwe[$key] = $input[$key];
                }
            }
            $recipient = array("encrypted_key" => $input["encrypted_key"]);
            if (array_key_exists("header", $input)) {
                $recipient["header"] = $input["header"];
            }
            $jwe["recipients"] = array($recipient);

            return $this->loadSerializedJsonJWE($jwe, $jwk_set);
        }
        throw new \InvalidArgumentException('Unable to load the input');
    }

    /**
     * @param string $input
     */
    protected function loadCompactSerializedJson($input, $verify_signature = true, JWKSetInterface $jwk_set = null)
    {
        $parts = explode('.', $input);

        switch (count($parts)) {
            case 3:
                // We suppose it is a JWS object
                $input = array(
                    "payload" => $parts[1],
                    "signatures" => array(
                        array(
                            "protected" => $parts[0],
                            "signature" => $parts[2],
                        ),
                    ),
                );

                return $this->loadSerializedJsonJWS($input, $verify_signature, $jwk_set);
            case 5:
                // We suppose it is a JWE object
                $input = array(
                    "protected" => $parts[0],
                    "recipients" => array(
                        array(
                            "encrypted_key" => $parts[1],
                        ),
                    ),
                    "iv" => $parts[2],
                    "ciphertext" => $parts[3],
                    "tag" => $parts[4],
                );

                return $this->loadSerializedJsonJWE($input, $jwk_set);
            default:
                throw new \InvalidArgumentException('Unable to load the input');
        }
    }

    /**
     * @param array $data
     */
    protected function loadSerializedJsonJWS($data, $verify_signature = true, JWKSetInterface $jwk_set = null)
    {
        $encoded_payload = $data['payload'];
        $payload = Base64Url::decode($encoded_payload);

        foreach ($data['signatures'] as $signature) {
            if (array_key_exists("protected", $signature)) {
                $encoded_protected_header = $signature['protected'];
                $protected_header = json_decode(Base64Url::decode($encoded_protected_header), true);
            } else {
                $encoded_protected_header = null;
                $protected_header = array();
            }
            $unprotected_header = isset($signature['header']) ? $signature['header'] : array();

            $jwt_signature = Base64Url::decode($signature['signature']);
            if (false === $verify_signature || true === $this->verifySignature($encoded_protected_header, $unprotected_header, $encoded_payload, $jwt_signature, $jwk_set)) {
                return $this->createJWS($protected_header, $unprotected_header, $payload);
            }
        }
    }

    protected function createJWS($protected_header, $unprotected_header, $payload)
    {
        $complete_header = array_merge($protected_header, $unprotected_header);
        $this->convertJWTContent($complete_header, $payload);
        $jws = $this->getJWTManager()->createJWS();
        $jws->setPayload($payload);
        if (!empty($protected_header)) {
            $jws->setProtectedHeader($protected_header);
        }
        if (!empty($unprotected_header)) {
            $jws->setUnprotectedHeader($unprotected_header);
        }

        return $jws;
    }

    /**
     * @param string $signature
     */
    protected function verifySignature($protected_header, $unprotected_header, $payload, $signature, JWKSetInterface $jwk_set = null)
    {
        if ($protected_header === null && $unprotected_header === null) {
            throw new \InvalidArgumentException('Invalid header');
        }
        $input = $protected_header.".".$payload;

        $complete_header = array();
        if ($protected_header !== null) {
            $tmp = json_decode(Base64Url::decode($protected_header), true);
            if (!is_array($tmp)) {
                throw new \InvalidArgumentException('Invalid protected header');
            }
            $complete_header = array_merge($complete_header, $tmp);
        }
        if ($unprotected_header !== null) {
            $complete_header = array_merge($complete_header, $unprotected_header);
        }

        if (null === $jwk_set) {
            $jwk_set = $this->getJWKManager()->findByHeader($complete_header);
        }
        if (empty($jwk_set)) {
            return false;
        }
        $algorithm = $this->getJWAManager()->getAlgorithm($complete_header["alg"]);
        if (!$algorithm instanceof SignatureInterface) {
            throw new \RuntimeException("The algorithm '".$complete_header["alg"]."' does not implement SignatureInterface.");
        }

        foreach ($jwk_set->getKeys() as $jwk) {
            if ($algorithm->verify($jwk, $input, $signature)) {
                return true;
            }
        }

        return false;
    }

    public function decryptCEK(JWAInterface $key_encryption_algorithm, JWAInterface $content_encryption_algorithm, JWKInterface $key, $encrypted_cek, array $header)
    {
        if ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            return $key_encryption_algorithm->getCEK($key, $header);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            return $key_encryption_algorithm->getAgreementKey($key, $content_encryption_algorithm->getCEKSize(), $header);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $key_encryption_algorithm->unwrapAgreementKey($key, $encrypted_cek, $content_encryption_algorithm->getCEKSize(), $header);
        } elseif ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $key_encryption_algorithm->decryptKey($key, $encrypted_cek, $header);
        }
    }

    /**
     * @param array $data
     */
    protected function loadSerializedJsonJWE($data, JWKSetInterface $jwk_set = null)
    {
        $ciphertext = Base64Url::decode($data['ciphertext']);
        if (array_key_exists("unprotected", $data)) {
            $unprotected_header = $data['unprotected'];
        } else {
            $unprotected_header = array();
        }
        $protected = array_key_exists("protected", $data) ? json_decode(Base64Url::decode($data['protected']), true) : array();
        $unprotected = array_key_exists("unprotected", $data) ? $data['unprotected'] : array();
        $aad = array_key_exists("aad", $data) ? Base64Url::decode($data['aad']) : null;
        $tag = array_key_exists("tag", $data) ? Base64Url::decode($data['tag']) : null;
        $iv  = array_key_exists("iv", $data) ? Base64Url::decode($data['iv']) : null;

        foreach ($data['recipients'] as $recipient) {
            $encrypted_key = Base64Url::decode($recipient['encrypted_key']);
            $header = array_key_exists("header", $recipient) ? $recipient['header'] : array();
            $complete_header = array_merge($protected, $unprotected, $header);

            if (!array_key_exists("alg", $complete_header) || !array_key_exists("enc", $complete_header)) {
                throw new \InvalidArgumentException("Parameters 'enc' or 'alg' are missing.");
            }
            if (null === $jwk_set) {
                $jwk_set = $this->getJWKManager()->findByHeader($complete_header);
            }
            $key_encryption_algorithm     = $this->getJWAManager()->getAlgorithm($complete_header["alg"]);
            $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_header["enc"]);
            if (!$content_encryption_algorithm instanceof ContentEncryptionInterface) {
                throw new \RuntimeException("The algorithm '".$complete_header["enc"]."' does not implement ContentEncryptionInterface.");
            }

            foreach ($jwk_set as $key) {
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $key, $encrypted_key, $complete_header);
                if ($cek !== null) {
                    $payload = $content_encryption_algorithm->decryptContent($ciphertext, $cek, $iv, $aad, $complete_header, $tag);

                    if (array_key_exists("zip", $complete_header)) {
                        $method = $this->getCompressionManager()->getCompressionAlgorithm($complete_header['zip']);
                        if ($method === null) {
                            throw new \RuntimeException("Compression method '".$complete_header['zip']."' not supported");
                        }
                        $payload = $method->uncompress($payload);
                        if (!is_string($payload)) {
                            throw new \RuntimeException("Decompression failed");
                        }
                    }

                    $this->convertJWTContent($complete_header, $payload);

                    $jwe = $this->getJWTManager()->createJWE();
                    $jwe->setProtectedHeader($protected)
                        ->setUnprotectedHeader(array_merge($unprotected_header, $header))
                        ->setPayload($payload);

                    return $jwe;
                }
            }
        }
    }

    protected function convertJWTContent(array $header, &$payload)
    {
        //The payload is a JWKSet or JWK object
        if (array_key_exists("cty", $header)) {
            switch ($header['cty']) {
                case 'jwk+json':
                    $payload = $this->getJWKManager()->createJWK(json_decode($payload, true));

                    return;
                case 'jwkset+json':
                    $values = json_decode($payload, true);
                    if (!array_key_exists("keys", $values)) {
                        throw new \Exception("Not a valid key set");
                    }
                    $payload = $this->getJWKManager()->createJWKSet($values['keys']);

                    return;
                default:
                    break;
            }
        }

        //The payload is a JSON array
        $json = json_decode($payload, true);
        if (is_array($json)) {
            $payload = $json;

            return;
        }
    }
}