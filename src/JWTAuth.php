<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean ifs <ifs148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ifs\JWTAuth;

use ifs\JWTAuth\Contracts\Providers\Auth;
use ifs\JWTAuth\Http\Parser\Parser;

/** @deprecated */
class JWTAuth extends JWT
{
    /**
     * The authentication provider.
     *
     * @var \ifs\JWTAuth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * Constructor.
     *
     * @param  \ifs\JWTAuth\Manager  $manager
     * @param  \ifs\JWTAuth\Contracts\Providers\Auth  $auth
     * @param  \ifs\JWTAuth\Http\Parser\Parser  $parser
     * @return void
     */
    public function __construct(Manager $manager, Auth $auth, Parser $parser)
    {
        parent::__construct($manager, $parser);
        $this->auth = $auth;
    }

    /**
     * Attempt to authenticate the user and return the token.
     *
     * @param  array  $credentials
     * @return false|string
     */
    public function attempt(array $credentials)
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->user());
    }

    /**
     * Authenticate a user via a token.
     *
     * @return \ifs\JWTAuth\Contracts\JWTSubject|false
     */
    public function authenticate()
    {
        $id = $this->getPayload()->get('sub');

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->user();
    }

    /**
     * Alias for authenticate().
     *
     * @return \ifs\JWTAuth\Contracts\JWTSubject|false
     */
    public function toUser()
    {
        return $this->authenticate();
    }

    /**
     * Get the authenticated user.
     *
     * @return \ifs\JWTAuth\Contracts\JWTSubject
     */
    public function user()
    {
        return $this->auth->user();
    }
}
