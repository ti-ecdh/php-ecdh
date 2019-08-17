<?php declare(strict_types=1);
/**
 *
 * This file is part of the ti-ecdh/php-ecdh  package.
 *
 * (c) ti-ecdh <https://github.com/ti-ecdh>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Ti\ECDH\Kernel;

use Ti\ECDH\Support\Math;

/**
 * @author  Hamza ESSAYEGH <hamza.essayegh@protonmail.com>
 */
abstract class ECDH
{
    /**
     * @var DomainParameters
     */
    protected $dp;

    /**
     * @var \GMP
     */
    protected $private;

    /**
     * @var \GMP[]
     */
    protected $public;

    /**
     * @var \GMP
     */
    protected $secret;

    /**
     * @var string
     */
    protected $algoUsed = 'haval256,5';

    /**
     * The shared secret is xk (the x coordinate of the point)
     *
     * @param \GMP[] $public_external
     */
    public function computeSecret($public_external)
    {
        $this->secret = Math::scalarMulti($this->private, $public_external)[0];
    }

    /**
     * Sign a given message with private key
     *
     * @param string $message
     *
     * @return ECDHSignature
     */
    public function signMessage($message)
    {
        // creating the signature object
        $sign = new ECDHSignature();

        // hash of the message
        $z = gmp_init(hash($this->algoUsed, $message), 16);

        do {
            // take a random integer k between 1,n-1
            $k = gmp_random_range(gmp_init(1), gmp_sub($this->dp->getN(), gmp_init(1)));

            // calculate the point P = kG
            $p = Math::scalarMulti($k, $this->dp->getG());

            // calculate the number r = xp mod n
            $r = gmp_mod($p[0], $this->dp->getN());

            // if r = 0, choose another k
            if (0 == $r) {
                continue;
            }

            // calculate s = k^(-1) * (z + rdA) mod n
            $s   = gmp_invert($k, $this->dp->getN());
            $rda = gmp_mul($r, $this->private);
            $s   = gmp_mul($s, gmp_add($z, $rda));
        } while (0 == $r && 0 == $s); // if r=0 or s=0, choose another k

        // setting parameters
        $sign
            ->setR($r)
            ->setS($s);

        return $sign;
    }

    /**
     * Verify a signature with an external public key
     *
     * @param ECDHSignature $sign
     * @param \GMP[]        $pub_ext
     * @param string        $message
     *
     * @return bool
     */
    public function verifySignature(ECDHSignature $sign, $pub_ext, $message)
    {
        // hashing
        $z    = gmp_init(hash($this->algoUsed, $message), 16);

        $sinv = gmp_invert($sign->getS(), $this->dp->getN());
        $u1   = gmp_mod(gmp_mul($sinv, $z), $this->dp->getN());
        $u2   = gmp_mod(gmp_mul($sinv, $sign->getR()), $this->dp->getN());

        $p = Math::addVector(
            Math::scalarMulti($u1, $this->dp->getG()),
            Math::scalarMulti($u2, $pub_ext)
        );

        // the signature is valid only if r = xp mod n
        $expected = gmp_mod($p[0], $this->dp->getN());

        // checking if signature is valid
        return 0 == gmp_cmp($sign->getR(), $expected);
    }

    /**
     * @return \GMP
     */
    public function getPrivate()
    {
        return $this->private;
    }

    /**
     * @param \GMP $private
     *
     * @return ECDH
     */
    public function setPrivate($private)
    {
        $this->private = $private;

        return $this;
    }

    /**
     * @return \GMP[]
     */
    public function getPublic()
    {
        return $this->public;
    }

    /**
     * @param \GMP[] $public
     *
     * @return ECDH
     */
    public function setPublic($public)
    {
        $this->public = $public;

        return $this;
    }

    /**
     * @return \GMP
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * @param \GMP $secret
     *
     * @return ECDH
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }
}
