<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean ifs <ifs148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ifs\JWTAuth\Claims;

use ifs\JWTAuth\Exceptions\InvalidClaimException;
use ifs\JWTAuth\Exceptions\TokenExpiredException;
use ifs\JWTAuth\Exceptions\TokenInvalidException;

class IssuedAt extends Claim
{
    use DatetimeTrait {
        validateCreate as commonValidateCreate;
    }

    /**
     * {@inheritdoc}
     */
    protected $name = 'iat';

    /**
     * {@inheritdoc}
     */
    public function validateCreate($value)
    {
        $this->commonValidateCreate($value);

        if ($this->isFuture($value)) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }

    /**
     * {@inheritdoc}
     */
    public function validatePayload()
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException('Issued At (iat) timestamp cannot be in the future');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function validateRefresh($refreshTTL)
    {
        if ($this->isPast($this->getValue() + $refreshTTL * 60)) {
            throw new TokenExpiredException('Token has expired and can no longer be refreshed');
        }
    }
}
