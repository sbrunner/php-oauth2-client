<?php

/*
 * Copyright (c) 2017, 2018 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace fkooman\OAuth\Client;

use fkooman\OAuth\Client\Exception\IdTokenException;
use ParagonIE\ConstantTime\Base64UrlSafe;

class IdToken
{
    /** @var string */
    private $iss;

    /** @var string */
    private $sub;

    /** @var string|array<string> */
    private $aud;

    /** @var int */
    private $exp;

    /** @var int */
    private $iat;

    /** @var int */
    private $authTime;

    /**
     * @param string               $iss
     * @param string               $sub
     * @param string|array<string> $aud
     * @param int                  $exp
     * @param int                  $iat
     * @param int                  $authTime
     */
    public function __construct($iss, $sub, $aud, $exp, $iat, $authTime)
    {
        $this->iss = $iss;
        $this->sub = $sub;
        $this->aud = $aud;
        $this->exp = $exp;
        $this->iat = $iat;
        $this->authTime = $authTime;
    }

    /**
     * @param string $jwtToken
     *
     * @return self
     */
    public static function decode($jwtToken)
    {
        $jwtParts = \explode('.', $jwtToken);
        if (3 !== \count($jwtParts)) {
            throw new IdTokenException('invalid JWT token');
        }
        $idTokenData = Util::decodeJson(Base64UrlSafe::decode($jwtParts[1]));
        foreach (['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time'] as $key) {
            if (!\array_key_exists($key, $idTokenData)) {
                throw new IdTokenException(\sprintf('missing "%s"', $key));
            }
        }
        if (!\is_string($idTokenData['iss'])) {
            throw new IdTokenException('"iss" must be string');
        }
        if (!\is_string($idTokenData['sub'])) {
            throw new IdTokenException('"sub" must be string');
        }
        if (!\is_string($idTokenData['aud']) && !\is_array($idTokenData['sub'])) {
            throw new IdTokenException('"aud" must be string or array<string>');
        }
        if (!\is_int($idTokenData['exp'])) {
            throw new IdTokenException('"exp" must be int');
        }
        if (!\is_int($idTokenData['iat'])) {
            throw new IdTokenException('"iat" must be int');
        }
        if (!\is_int($idTokenData['auth_time'])) {
            throw new IdTokenException('"auth_time" must be int');
        }

        return new self(
            $idTokenData['iss'],
            $idTokenData['sub'],
            $idTokenData['aud'],
            $idTokenData['exp'],
            $idTokenData['iat'],
            $idTokenData['auth_time']
        );
    }

    /**
     * @return string
     */
    public function getIss()
    {
        return $this->iss;
    }

    /**
     * @return string
     */
    public function getSub()
    {
        return $this->sub;
    }

    /**
     * @return string|array<string>
     */
    public function getAud()
    {
        return $this->aud;
    }

    /**
     * @return int
     */
    public function getExp()
    {
        return $this->exp;
    }

    /**
     * @return int
     */
    public function getIat()
    {
        return $this->iat;
    }

    /**
     * @return int
     */
    public function getAuthTime()
    {
        return $this->authTime;
    }

    /**
     * @param string $iss
     *
     * @return void
     */
    private function setIss($iss)
    {
        $this->iss = $iss;
    }

    /**
     * @param string $sub
     *
     * @return void
     */
    private function setSub($sub)
    {
        $this->sub = $sub;
    }

    /**
     * @param string|array<string> $aud
     *
     * @return void
     */
    private function setAud($aud)
    {
        $this->aud = $aud;
    }

    /**
     * @param int $exp
     *
     * @return void
     */
    private function setExp($exp)
    {
        $this->exp = $exp;
    }

    /**
     * @param int $iat
     *
     * @return void
     */
    private function setIat($iat)
    {
        $this->iat = $iat;
    }

    /**
     * @param int $authTime
     *
     * @return void
     */
    private function setAuthTime($authTime)
    {
        $this->authTime = $authTime;
    }
}
