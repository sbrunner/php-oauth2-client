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

use fkooman\OAuth\Client\Exception\TokenResponseException;
use fkooman\OAuth\Client\Http\Response;

class TokenResponse
{
    /** @var string */
    private $accessToken;

    /** @var string */
    private $tokenType;

    /** @var null|int */
    private $expiresIn;

    /** @var null|string */
    private $refreshToken;

    /** @var null|string */
    private $scope;

    /**
     * @param string      $accessToken
     * @param string      $tokenType
     * @param null|int    $expiresIn
     * @param null|string $refreshToken
     * @param null|string $scope
     */
    private function __construct($accessToken, $tokenType, $expiresIn, $refreshToken, $scope)
    {
        $this->setAccessToken($accessToken);
        $this->setTokenType($tokenType);
        $this->setExpiresIn($expiresIn);
        $this->setRefreshToken($refreshToken);
        $this->setScope($scope);
    }

    /**
     * @return string
     *
     * @see https://tools.ietf.org/html/rfc6749#section-5.1
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @return string
     *
     * @see https://tools.ietf.org/html/rfc6749#section-7.1
     */
    public function getTokenType()
    {
        return $this->tokenType;
    }

    /**
     * @return null|int
     *
     * @see https://tools.ietf.org/html/rfc6749#section-5.1
     */
    public function getExpiresIn()
    {
        return $this->expiresIn;
    }

    /**
     * @return null|string the refresh token
     *
     * @see https://tools.ietf.org/html/rfc6749#section-1.5
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return null|string
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @param \fkooman\OAuth\Client\Http\Response $response
     *
     * @return TokenResponse
     */
    public static function fromResponse(Response $response)
    {
        $tokenData = $response->json();
        if (!\is_array($tokenData)) {
            throw new TokenResponseException('response MUST be array');
        }
        $accessToken = self::requireString($tokenData, 'access_token');
        $tokenType = self::requireString($tokenData, 'token_type');
        $expiresIn = self::optionalInt($tokenData, 'expires_in');
        $refreshToken = self::optionalString($tokenData, 'refresh_token');
        $scope = self::optionalString($tokenData, 'scope');

        return new self(
            $accessToken,
            $tokenType,
            $expiresIn,
            $refreshToken,
            $scope
        );
    }

    /**
     * @param string $accessToken
     *
     * @return void
     */
    private function setAccessToken($accessToken)
    {
        // access-token = 1*VSCHAR
        // VSCHAR       = %x20-7E
        if (1 !== \preg_match('/^[\x20-\x7E]+$/', $accessToken)) {
            throw new TokenResponseException('invalid "access_token"');
        }
        $this->accessToken = $accessToken;
    }

    /**
     * @param string $tokenType
     *
     * @return void
     */
    private function setTokenType($tokenType)
    {
        if ('bearer' !== $tokenType && 'Bearer' !== $tokenType) {
            throw new TokenResponseException('unsupported "token_type"');
        }
        $this->tokenType = $tokenType;
    }

    /**
     * @param null|int $expiresIn
     *
     * @return void
     */
    private function setExpiresIn($expiresIn)
    {
        if (null !== $expiresIn) {
            if (0 >= $expiresIn) {
                throw new TokenResponseException('invalid "expires_in"');
            }
        }
        $this->expiresIn = $expiresIn;
    }

    /**
     * @param null|string $refreshToken
     *
     * @return void
     */
    private function setRefreshToken($refreshToken)
    {
        if (null !== $refreshToken) {
            // refresh-token = 1*VSCHAR
            // VSCHAR        = %x20-7E
            if (1 !== \preg_match('/^[\x20-\x7E]+$/', $refreshToken)) {
                throw new TokenResponseException('invalid "refresh_token"');
            }
        }
        $this->refreshToken = $refreshToken;
    }

    /**
     * @param null|string $scope
     *
     * @return void
     */
    private function setScope($scope)
    {
        if (null !== $scope) {
            // scope       = scope-token *( SP scope-token )
            // scope-token = 1*NQCHAR
            // NQCHAR      = %x21 / %x23-5B / %x5D-7E
            foreach (\explode(' ', $scope) as $scopeToken) {
                if (1 !== \preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scopeToken)) {
                    throw new TokenResponseException('invalid "scope"');
                }
            }
        }
        $this->scope = $scope;
    }

    /**
     * @param array  $keyValue
     * @param string $keyName
     *
     * @return string
     */
    private static function requireString(array $keyValueList, $keyName)
    {
        if (!\array_key_exists($keyName, $keyValueList)) {
            throw new TokenResponseException(\sprintf('missing key "%s"', $keyName));
        }
        $keyValue = $keyValueList[$keyName];
        if (!\is_string($keyValue)) {
            throw new TokenResponseException(\sprintf('key "%s" not of type "string"', $keyName));
        }

        return $keyValue;
    }

    /**
     * @param array  $keyValue
     * @param string $keyName
     *
     * @return null|string
     */
    private static function optionalString(array $keyValueList, $keyName)
    {
        if (!\array_key_exists($keyName, $keyValueList)) {
            return null;
        }

        return self::requireString($keyValueList, $keyName);
    }

    /**
     * @param array  $keyValue
     * @param string $keyName
     *
     * @return null|int
     */
    private static function optionalInt(array $keyValueList, $keyName)
    {
        if (!\array_key_exists($keyName, $keyValueList)) {
            return null;
        }

        return self::requireInt($keyValueList, $keyName);
    }

    /**
     * @param array  $keyValue
     * @param string $keyName
     *
     * @return int
     */
    private static function requireInt(array $keyValueList, $keyName)
    {
        if (!\array_key_exists($keyName, $keyValueList)) {
            throw new TokenResponseException(\sprintf('missing key "%s"', $keyName));
        }
        $keyValue = $keyValueList[$keyName];
        if (!\is_int($keyValue)) {
            throw new TokenResponseException(\sprintf('key "%s" not of type "int"', $keyName));
        }

        return $keyValue;
    }
}
