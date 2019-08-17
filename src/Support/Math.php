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

namespace Ti\ECDH\Support;

/**
 * @author  Hamza ESSAYEGH <hamza.essayegh@protonmail.com>
 */
class Math
{
    /**
     * @param \GMP   $k
     * @param \GMP[] $v
     *
     * @return \GMP[]
     */
    public static function scalarMulti($k, array $v): array
    {
        return [
            gmp_mul($k, $v[0]),
            gmp_mul($k, $v[1]),
        ];
    }

    /**
     * @param \GMP[] $v1
     * @param \GMP[] $v2
     *
     * @return array
     */
    public static function addVector(array $v1, array $v2): array
    {
        return [
            gmp_add($v1[0], $v2[0]),
            gmp_add($v1[1], $v2[1]),
        ];
    }
}
