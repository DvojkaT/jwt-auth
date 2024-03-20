<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean ifs <ifs148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ifs\JWTAuth\Test\Providers\JWT;

use ifs\JWTAuth\Test\AbstractTestCase;
use ifs\JWTAuth\Test\Stubs\JWTProviderStub;

class ProviderTest extends AbstractTestCase
{
    /**
     * @var \ifs\JWTAuth\Test\Stubs\JWTProviderStub
     */
    protected $provider;

    public function setUp(): void
    {
        parent::setUp();

        $this->provider = new JWTProviderStub('secret', 'HS256', []);
    }

    /** @test */
    public function it_should_set_the_algo()
    {
        $this->provider->setAlgo('HS512');

        $this->assertSame('HS512', $this->provider->getAlgo());
    }

    /** @test */
    public function it_should_set_the_secret()
    {
        $this->provider->setSecret('foo');

        $this->assertSame('foo', $this->provider->getSecret());
    }
}
