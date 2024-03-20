<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean ifs <ifs148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ifs\JWTAuth\Test\Stubs;

use ifs\JWTAuth\Providers\JWT\Provider;

class JWTProviderStub extends Provider
{
    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        return false;
    }
}
