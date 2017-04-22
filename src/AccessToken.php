<?php

/**
 * Copyright (c) 2016, 2017 François Kooman <fkooman@tuxed.net>.
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

use DateTime;
use RuntimeException;

/**
 * AccessToken object containing the response from the OAuth 2.0 provider's
 * token response.
 */
class AccessToken
{
    /** @var string */
    private $accessToken;

    /** @var string */
    private $tokenType;

    /** @var string */
    private $scope;

    /** @var string|null */
    private $refreshToken;

    /** @var \DateTime */
    private $expiresAt;

    public function __construct($accessToken, $tokenType, $scope, $refreshToken, DateTime $expiresAt)
    {
        $this->accessToken = $accessToken;
        $this->tokenType = $tokenType;
        $this->scope = $scope;
        $this->refreshToken = $refreshToken;
        $this->expiresAt = $expiresAt;
    }

    /**
     * Get the access token.
     *
     * @return string the access token
     *
     * @see https://tools.ietf.org/html/rfc6749#section-5.1
     */
    public function getToken()
    {
        return $this->accessToken;
    }

    /**
     * Get the token type.
     *
     * @return string the token type
     *
     * @see https://tools.ietf.org/html/rfc6749#section-7.1
     */
    public function getTokenType()
    {
        return $this->tokenType;
    }

    /**
     * Get the scope.
     *
     * @return string the scope
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * Get the refresh token.
     *
     * @return string|null the refresh token
     *
     * @see https://tools.ietf.org/html/rfc6749#section-1.5
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return DateTime
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }

    /**
     * @param DateTime $dateTime
     *
     * @return bool
     */
    public function isExpired(DateTime $dateTime)
    {
        return $dateTime >= $this->expiresAt;
    }

    /**
     * @return string
     */
    public function json()
    {
        return json_encode(
            [
                'access_token' => $this->getToken(),
                'token_type' => $this->getTokenType(),
                'scope' => $this->getScope(),
                'refresh_token' => $this->getRefreshToken(),
                'expires_at' => $this->getExpiresAt()->format('Y-m-d H:i:s'),
            ]
        );
    }

    /**
     * @param string $jsonData
     *
     * @return AccessToken
     */
    public static function fromJson($jsonData)
    {
        $tokenData = json_decode($jsonData, true);
        if (is_null($tokenData) && JSON_ERROR_NONE !== json_last_error()) {
            $errorMsg = function_exists('json_last_error_msg') ? json_last_error_msg() : json_last_error();
            throw new RuntimeException(sprintf('unable to decode JSON: %s', $errorMsg));
        }

        if (!is_array($tokenData)) {
            throw new RuntimeException('JSON data MUST be an array');
        }

        $requiredKeys = ['access_token', 'token_type', 'scope', 'refresh_token', 'expires_at'];
        foreach ($requiredKeys as $key) {
            if (!array_key_exists($key, $tokenData)) {
                throw new RuntimeException(sprintf('missing key "%s" in JSON data', $key));
            }
        }

        return new self(
            $tokenData['access_token'],
            $tokenData['token_type'],
            $tokenData['scope'],
            $tokenData['refresh_token'],
            new DateTime($tokenData['expires_at'])
        );
    }
}
