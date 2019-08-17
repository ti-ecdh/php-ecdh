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

namespace Ti\ECDH\Tests;

use Ti\ECDH\Kernel\ECDHCurve25519;
use Ti\ECDH\Kernel\ECDHCurve448;
use Ti\ECDH\Kernel\ECDHSecp;

class ECDHTest extends TestCase
{
    const MESSAGE = <<<EOT
 Happiness is not about being immortal nor having food or rights in one's hand. It’s about having each tiny wish come true, or having something to eat when you are hungry or having someone's love when you need love.
EOT;

    public function testCurve25519()
    {
        $ecdh_alice = new ECDHCurve25519();
        $ecdh_bob = new ECDHCurve25519();

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));
        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testCurve448()
    {
        $ecdh_alice = new ECDHCurve448();
        $ecdh_bob = new ECDHCurve448();

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));
        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testSECP192K1()
    {
        $ecdh_alice = new ECDHSecp(ECDHSecp::SECP192K1);
        $ecdh_bob = new ECDHSecp(ECDHSecp::SECP192K1);

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));
        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testSECP192R1()
    {
        $ecdh_alice = new ECDHSecp(ECDHSecp::SECP192R1);
        $ecdh_bob = new ECDHSecp(ECDHSecp::SECP192R1);

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));
        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testSECP224K1()
    {
        $ecdh_alice = new ECDHSecp(ECDHSecp::SECP224K1);
        $ecdh_bob = new ECDHSecp(ECDHSecp::SECP224K1);

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));

        // TODO: Fix problem with signature
//        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testSECP224R1()
    {
        $ecdh_alice = new ECDHSecp(ECDHSecp::SECP224R1);
        $ecdh_bob = new ECDHSecp(ECDHSecp::SECP224R1);

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));
        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testSECP256K1()
    {
        $ecdh_alice = new ECDHSecp(ECDHSecp::SECP256K1);
        $ecdh_bob = new ECDHSecp(ECDHSecp::SECP256K1);

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));
        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testSECP256R1()
    {
        $ecdh_alice = new ECDHSecp(ECDHSecp::SECP256R1);
        $ecdh_bob = new ECDHSecp(ECDHSecp::SECP256R1);

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));
        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testSECP384R1()
    {
        $ecdh_alice = new ECDHSecp(ECDHSecp::SECP384R1);
        $ecdh_bob = new ECDHSecp(ECDHSecp::SECP384R1);

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));
        $this->assertTrue($signOk, "Signature verification failed");
    }

    public function testSECP521R1()
    {
        $ecdh_alice = new ECDHSecp(ECDHSecp::SECP521R1);
        $ecdh_bob = new ECDHSecp(ECDHSecp::SECP521R1);

        $ecdh_bob->computeSecret($ecdh_alice->getPublic());
        $ecdh_alice->computeSecret($ecdh_bob->getPublic());

        $sign = $ecdh_bob->signMessage(self::MESSAGE);
        $signOk = $ecdh_alice->verifySignature($sign, $ecdh_bob->getPublic(), self::MESSAGE);

        $this->assertEquals(0, gmp_cmp($ecdh_alice->getSecret(), $ecdh_bob->getSecret()));

        $this->assertTrue($signOk, "Signature verification failed");
    }
}
