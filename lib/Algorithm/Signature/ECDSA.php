<?php

namespace SpomkyLabs\JOSE\Algorithm\Signature;

use Jose\JWKInterface;
use Jose\Operation\SignatureInterface;
use Mdanter\Ecc\Point;
use Mdanter\Ecc\PublicKey;
use Mdanter\Ecc\PrivateKey;
use Mdanter\Ecc\Signature;
use Mdanter\Ecc\EccFactory;
use SpomkyLabs\JOSE\Util\Base64Url;

/**
 */
abstract class ECDSA implements SignatureInterface
{
    /**
     * @inheritdoc
     */
    public function sign(JWKInterface $key, $data)
    {
        $this->checkKey($key);
        $adapter = EccFactory::getAdapter();

        $p     = $this->getGenerator();
        $curve = $this->getCurve();
        $x     = $this->convertBase64ToDec($key->getValue('x'));
        $y     = $this->convertBase64ToDec($key->getValue('y'));
        $d     = $this->convertBase64ToDec($key->getValue('d'));
        $hash  = $this->convertHexToDec(hash($this->getHashAlgorithm(), $data));

        $k = $adapter->rand($p->getOrder());

        $public_key = new PublicKey($p, new Point($curve, $x, $y, $p->getOrder(), $adapter), $adapter);
        $private_key = new PrivateKey($public_key, $d, $adapter);
        $sign = $private_key->sign($hash, $k);

        $part_length = $this->getSignaturePartLength();

        $R = str_pad($this->convertDecToHex($sign->getR()), $part_length, "0", STR_PAD_LEFT);
        $S = str_pad($this->convertDecToHex($sign->getS()), $part_length, "0", STR_PAD_LEFT);

        return $this->convertHextoBin($R.$S);
    }

    /**
     * @inheritdoc
     */
    public function verify(JWKInterface $key, $data, $signature)
    {
        $this->checkKey($key);
        $signature = $this->convertBinToHex($signature);
        $part_length = $this->getSignaturePartLength();
        if (strlen($signature) !== 2*$part_length) {
            return false;
        }

        $adapter = EccFactory::getAdapter();

        $p     = $this->getGenerator();
        $curve = $this->getCurve();
        $x     = $this->convertBase64ToDec($key->getValue('x'));
        $y     = $this->convertBase64ToDec($key->getValue('y'));
        $R     = $this->convertHexToDec(substr($signature, 0, $part_length));
        $S     = $this->convertHexToDec(substr($signature, $part_length));
        $hash  = $this->convertHexToDec(hash($this->getHashAlgorithm(), $data));

        $public_key = new PublicKey($p, new Point($curve, $x, $y, $p->getOrder(), $adapter), $adapter);

        return $public_key->verifies($hash, new Signature($R, $S));
    }

    abstract protected function getCurve();
    abstract protected function getGenerator();

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();
    abstract protected function getSignaturePartLength();

    /**
     * @param string $value
     */
    protected function convertHexToBin($value)
    {
        return pack("H*", $value);
    }

    /**
     * @param string $value
     */
    protected function convertBinToHex($value)
    {
        $value = unpack('H*', $value);

        return $value[1];
    }

    /**
 * @return string
 */
protected function convertDecToHex($value)
    {
        $adapter = EccFactory::getAdapter();

        return $adapter->decHex($value);
    }

    protected function convertHexToDec($value)
    {
        $adapter = EccFactory::getAdapter();

        return $adapter->hexDec($value);
    }

    protected function convertBase64ToDec($value)
    {
        $value = unpack('H*', Base64Url::decode($value));

        return $this->convertHexToDec($value[1]);
    }

    protected function checkKey(JWKInterface $key)
    {
        if ("EC" !== $key->getKeyType()) {
            throw new \InvalidArgumentException("The key is not valid");
        }
    }
}
