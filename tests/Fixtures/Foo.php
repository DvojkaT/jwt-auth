<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean ifs <ifs148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ifs\JWTAuth\Test\Fixtures;

use ifs\JWTAuth\Claims\Claim;

class Foo extends Claim
{
    /**
     * {@inheritdoc}
     */
    protected $name = 'foo';
}
