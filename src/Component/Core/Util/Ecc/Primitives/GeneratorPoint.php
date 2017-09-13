<?php

namespace Jose\Component\Core\Util\Ecc\Primitives;

use Jose\Component\Core\Util\Ecc\Math\GmpMath;
use Jose\Component\Core\Util\Ecc\Crypto\Key\PrivateKey;
use Jose\Component\Core\Util\Ecc\Crypto\Key\PublicKey;
use Jose\Component\Core\Util\Ecc\Random\RandomNumberGenerator;

/**
 * Curve point from which public and private keys can be derived.
 */
final class GeneratorPoint extends Point
{
    /**
     * @var RandomNumberGenerator|null
     */
    private $generator;

    /**
     * @param GmpMath $adapter
     * @param CurveFp $curve
     * @param \GMP    $x
     * @param \GMP    $y
     * @param \GMP    $order
     */
    public function __construct(
        GmpMath $adapter,
        CurveFp $curve,
        \GMP $x,
        \GMP $y,
        \GMP $order
    ) {
        $this->generator = new RandomNumberGenerator();
        parent::__construct($adapter, $curve, $x, $y, $order);
    }

    /**
     * Verifies validity of given coordinates against the current point and its point.
     *
     * @todo   Check if really necessary here (only used for testing in lib)
     * @param  \GMP $x
     * @param  \GMP $y
     * @return boolean
     */
    public function isValid(\GMP $x, \GMP $y)
    {
       
        $math = $this->getAdapter();

        $n = $this->getOrder();
        $zero = gmp_init(0, 10);
        $curve = $this->getCurve();

        if ($math->cmp($x, $zero) < 0 || $math->cmp($n, $x) <= 0 || $math->cmp($y, $zero) < 0 || $math->cmp($n, $y) <= 0) {
            return false;
        }

        if (! $curve->contains($x, $y)) {
            return false;
        }

        $point = $curve->getPoint($x, $y)->mul($n);

        if (! $point->isInfinity()) {
            return false;
        }

        return true;
    }

    /**
     * @return PrivateKey
     */
    public function createPrivateKey()
    {
        $secret = $this->generator->generate($this->getOrder());

        return new PrivateKey($this->getAdapter(), $this, $secret);
    }

    /**
     * @param \GMP $x
     * @param \GMP $y
     * @param \GMP $order
     * @return PublicKey
     */
    public function getPublicKeyFrom(\GMP $x, \GMP $y, \GMP $order = null)
    {
        $pubPoint = $this->getCurve()->getPoint($x, $y, $order);
        return new PublicKey($this->getAdapter(), $this, $pubPoint);
    }

    /**
     * @param \GMP $secretMultiplier
     * @return PrivateKey
     */
    public function getPrivateKeyFrom(\GMP $secretMultiplier)
    {
        return new PrivateKey($this->getAdapter(), $this, $secretMultiplier);
    }
}
