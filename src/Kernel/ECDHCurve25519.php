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
class ECDHCurve25519 extends ECDH
{
    /**
     * Curve25519 constructor.
     */
    public function __construct()
    {
        $this->dp = new DomainParameters();
        $this->dp
            ->setP(gmp_sub(gmp_pow('2', 255), gmp_init(19)))
            ->setA(gmp_init(486662))
            ->setB(gmp_init(1))
            ->setN(gmp_add(
                gmp_pow('2', 252),
                gmp_init('14def9dea2f79cd65812631a5cf5d3ed', 16)
            ))
            ->setH(gmp_init(8))
            ->setG([
                gmp_init(9),
                gmp_init('14781619447589544791020593568409986887264606134616475288964881837755586237401'),
            ])
        ;

        // generating private key
        $this->private = gmp_random_range(
            gmp_init(1),
            gmp_sub($this->dp->getN(), gmp_init(1))
        );

        // generating public key
        $this->public = Math::scalarMulti($this->private, $this->dp->getG());
    }
}
