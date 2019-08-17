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

use winwin\support\Arrayable;
use winwin\support\ArrayableTrait;
use winwin\support\Attribute;

/**
 * @author  Hamza ESSAYEGH <hamza.essayegh@protonmail.com>
 */
class DomainParameters extends Attribute implements Arrayable
{
    use ArrayableTrait;

    /**
     * @var \GMP
     */
    private $p;

    /**
     * @var \GMP
     */
    private $a;

    /**
     * @var \GMP
     */
    private $b;

    /**
     * @var \GMP[]
     */
    private $g;

    /**
     * @var \GMP
     */
    private $n;

    /**
     * @var \GMP
     */
    private $h;

    /**
     * DomainParameters constructor.
     *
     * @param \GMP   $p
     * @param \GMP   $a
     * @param \GMP   $b
     * @param \GMP[] $g
     * @param \GMP   $n
     * @param \GMP   $h
     * @param array  $attributes
     */
    public function __construct(
        \GMP $p = null,
        \GMP $a = null,
        \GMP $b = null,
        array $g = null,
        \GMP $n = null,
        \GMP $h = null,
        array $attributes = []
    ) {
        parent::__construct($attributes);
        $this->p = $p;
        $this->a = $a;
        $this->b = $b;
        $this->g = $g;
        $this->n = $n;
        $this->h = $h;
    }

    /**
     * @return \GMP
     */
    public function getP()
    {
        return $this->p;
    }

    /**
     * @param  \GMP             $p
     * @return DomainParameters
     */
    public function setP(\GMP $p): DomainParameters
    {
        $this->p = $p;

        return $this;
    }

    /**
     * @return \GMP
     */
    public function getA()
    {
        return $this->a;
    }

    /**
     * @param  \GMP             $a
     * @return DomainParameters
     */
    public function setA(\GMP $a): DomainParameters
    {
        $this->a = $a;

        return $this;
    }

    /**
     * @return \GMP
     */
    public function getB()
    {
        return $this->b;
    }

    /**
     * @param  \GMP             $b
     * @return DomainParameters
     */
    public function setB(\GMP $b): DomainParameters
    {
        $this->b = $b;

        return $this;
    }

    /**
     * @return \GMP[]
     */
    public function getG()
    {
        return $this->g;
    }

    /**
     * @param  \GMP[]           $g
     * @return DomainParameters
     */
    public function setG(array $g): DomainParameters
    {
        $this->g = $g;

        return $this;
    }

    /**
     * @return \GMP
     */
    public function getN()
    {
        return $this->n;
    }

    /**
     * @param  \GMP             $n
     * @return DomainParameters
     */
    public function setN(\GMP $n): DomainParameters
    {
        $this->n = $n;

        return $this;
    }

    /**
     * @return \GMP
     */
    public function getH()
    {
        return $this->h;
    }

    /**
     * @param  \GMP             $h
     * @return DomainParameters
     */
    public function setH(\GMP $h): DomainParameters
    {
        $this->h = $h;

        return $this;
    }
}
