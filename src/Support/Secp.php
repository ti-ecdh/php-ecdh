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

/**
 * Eliptic Curve Domain Paramaters over Fp
 *
 * Note:
 *      - ECDP = Elliptic Curve Domain Parameters
 *
 * @link http://www.secg.org/sec2-v2.pdf
 */

namespace Ti\ECDH\Support;

use Ti\ECDH\Kernel\DomainParameters;

/**
 * @author  Hamza ESSAYEGH <hamza.essayegh@protonmail.com>
 */
class Secp
{
    /**
     * Recommended Parameters secp192k1 (192-bit)
     *
     * @return DomainParameters
     */
    public static function secp192k1()
    {
        return new DomainParameters(
            gmp_init("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", 16),
            gmp_init("000000000000000000000000000000000000000000000000", 16),
            gmp_init("000000000000000000000000000000000000000000000003", 16),
            [
                gmp_init("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", 16),
                gmp_init("9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", 16),
            ],
            gmp_init("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", 16),
            gmp_init("01")
        );
    }

    /**
     * Recommended Parameters secp192r1 (192-bit)
     *
     * @return DomainParameters
     */
    public static function secp192r1()
    {
        return new DomainParameters(
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF', 16),
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC', 16),
            gmp_init('64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1', 16),
            [
                gmp_init('188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012', 16),
                gmp_init('07192B95FFC8DA78631011ED6B24CDD573F977A11E794811', 16),
            ],
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831', 16),
            gmp_init(1)
        );
    }

    /**
     * Recommended Parameters secp224k1 (224-bit)
     * TODO: Fix signature verification problem
     *
     * @return DomainParameters
     */
    public static function secp224k1()
    {
        return new DomainParameters(
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D', 16),
            gmp_init('00000000000000000000000000000000000000000000000000000000', 16),
            gmp_init('00000000000000000000000000000000000000000000000000000005', 16),
            [
                gmp_init('A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C', 16),
                gmp_init('7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5', 16),
            ],
            gmp_init('0000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7', 16),
            gmp_init(1)
        );
    }

    /**
     * Recommended Parameters secp224r1 (224-bit)
     *
     * @return DomainParameters
     */
    public static function secp224r1()
    {
        return new DomainParameters(
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001', 16),
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE', 16),
            gmp_init('B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4', 16),
            [
                gmp_init('B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21', 16),
                gmp_init('BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34', 16),
            ],
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D', 16),
            gmp_init(1)
        );
    }

    /**
     * Recommended Parameters secp256k1 (256-bit)
     *
     * Used by Bitcoin for digital signature
     *
     * @return DomainParameters
     */
    public static function secp256k1()
    {
        return new DomainParameters(
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16),
            gmp_init('0000000000000000000000000000000000000000000000000000000000000000', 16),
            gmp_init('0000000000000000000000000000000000000000000000000000000000000007', 16),
            [
                gmp_init('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16),
                gmp_init('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16),
            ],
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16),
            gmp_init(1)
        );
    }

    /**
     * Recommended Parameters secp256r1 (256-bit)
     *
     * @return DomainParameters
     */
    public static function secp256r1()
    {
        return new DomainParameters(
            gmp_init('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16),
            gmp_init('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC', 16),
            gmp_init('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B', 16),
            [
                gmp_init('6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296', 16),
                gmp_init('4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5', 16),
            ],
            gmp_init('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16),
            gmp_init(1)
        );
    }

    /**
     * Recommended Parameters secp384r1 (384-bit)
     *
     * @return DomainParameters
     */
    public static function secp384r1()
    {
        return new DomainParameters(
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF', 16),
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC', 16),
            gmp_init('B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF', 16),
            [
                gmp_init('AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7', 16),
                gmp_init('3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F', 16),
            ],
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973', 16),
            gmp_init(1)
        );
    }

    /**
     * Recommended Parameters secp521r1 (521-bit)
     * TODO: Fix signature verification problem
     *
     * @return DomainParameters
     */
    public static function secp521r1()
    {
        return new DomainParameters(
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16),
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC', 16),
            gmp_init('953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00', 16),
            [
                gmp_init('00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66', 16),
                gmp_init('011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650', 16),
            ],
            gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409', 16),
            gmp_init(1)
        );
    }
}
