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

/**
 * @author  Hamza ESSAYEGH <hamza.essayegh@protonmail.com>
 */
class ECDHSignature
{
    /**
     * @var \GMP
     */
    private $r;

    /**
     * @var \GMP
     */
    private $s;

    /**
     * ECDHSignature constructor.
     *
     * @param \GMP $r
     * @param \GMP $s
     */
    public function __construct(\GMP $r = null, \GMP $s = null)
    {
        $this->r = $r;
        $this->s = $s;
    }

    /**
     * @return \GMP
     */
    public function getR()
    {
        return $this->r;
    }

    /**
     * @param \GMP $r
     *
     * @return ECDHSignature
     */
    public function setR($r)
    {
        $this->r = $r;

        return $this;
    }

    /**
     * @return \GMP
     */
    public function getS()
    {
        return $this->s;
    }

    /**
     * @param \GMP $s
     *
     * @return ECDHSignature
     */
    public function setS($s)
    {
        $this->s = $s;

        return $this;
    }
}
