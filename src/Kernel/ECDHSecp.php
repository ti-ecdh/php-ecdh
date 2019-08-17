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
use Ti\ECDH\Support\Secp;

/**
 * @author  Hamza ESSAYEGH <hamza.essayegh@protonmail.com>
 */
class ECDHSecp extends ECDH
{
    const SECP192K1 = 'secp192k1';
    const SECP192R1 = 'secp192r1';
    const SECP224K1 = 'secp224k1';
    const SECP224R1 = 'secp224r1';
    const SECP256K1 = 'secp256k1';
    const SECP256R1 = 'secp256r1';
    const SECP384R1 = 'secp384r1';
    const SECP521R1 = 'secp521r1';

    const HASH_ALGO = 'haval256,5';

    /**
     * ECDH constructor.
     *
     * @param string $standard
     */
    public function __construct($standard = self::SECP256K1)
    {
        // setting domain parameters
        $this->dp = call_user_func(Secp::class . '::' . $standard);

        // private key generation
        $this->private = gmp_random_range(
            gmp_init(1),
            gmp_sub($this->dp->getN(), gmp_init(1))
        );

        // public key generation
        $this->public  = Math::scalarMulti($this->private, $this->dp->getG());
    }
}
