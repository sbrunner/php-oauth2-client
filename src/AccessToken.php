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

use DateInterval;
use DateTime;
use fkooman\OAuth\Client\Exception\AccessTokenException;

class AccessToken
{
    /** @var string */
    private $providerId;

    /** @var \DateTime */
    private $issuedAt;

    /** @var string */
    private $accessToken;

    /** @var string */
    private $tokenType;

    /** @var int|null */
    private $expiresIn = null;

    /** @var string|null */
    private $refreshToken = null;

    /** @var string|null */
    private $scope = null;

    /**
     * @param array $tokenData
     */
    public function __construct(array $tokenData)
    {
        $requiredKeys = ['provider_id', 'issued_at', 'access_token', 'token_type'];
        foreach ($requiredKeys as $requiredKey) {
            if (!array_key_exists($requiredKey, $tokenData)) {
                throw new AccessTokenException(sprintf('missing key "%s"', $requiredKey));
            }
        }

        // set required keys
        $this->setProviderId($tokenData['provider_id']);
        $this->setIssuedAt($tokenData['issued_at']);
        $this->setAccessToken($tokenData['access_token']);
        $this->setTokenType($tokenData['token_type']);

        // set optional keys
        if (array_key_exists('expires_in', $tokenData)) {
            $this->setExpiresIn($tokenData['expires_in']);
        }
        if (array_key_exists('refresh_token', $tokenData)) {
            $this->setRefreshToken($tokenData['refresh_token']);
        }
        if (array_key_exists('scope', $tokenData)) {
            $this->setScope($tokenData['scope']);
        }
    }

    /**
     * @param Provider  $provider
     * @param \DateTime $dateTime
     * @param array     $tokenData
     * @param string    $scope
     */
    public static function fromCodeResponse(Provider $provider, DateTime $dateTime, array $tokenData, $scope)
    {
        $tokenData['provider_id'] = $provider->getProviderId();

        // if the scope was not part of the response, add the request scope,
        // because according to the RFC, if the scope is ommitted the requested
        // scope was granted!
        if (!array_key_exists('scope', $tokenData)) {
            $tokenData['scope'] = $scope;
        }
        // add the current DateTime as well to be able to figure out if the
        // token expired
        $tokenData['issued_at'] = $dateTime->format('Y-m-d H:i:s');

        return new self($tokenData);
    }

    /**
     * @param Provider    $provider
     * @param \DateTime   $dateTime
     * @param array       $tokenData
     * @param AccessToken $accessToken to steal the old scope and refresh_token from!
     */
    public static function fromRefreshResponse(Provider $provider, DateTime $dateTime, array $tokenData, AccessToken $accessToken)
    {
        $tokenData['provider_id'] = $provider->getProviderId();

        // if the scope is not part of the response, add the request scope,
        // because according to the RFC, if the scope is ommitted the requested
        // scope was granted!
        if (!array_key_exists('scope', $tokenData)) {
            $tokenData['scope'] = $accessToken->getScope();
        }
        // if the refresh_token is not part of the response, we wil reuse the
        // existing refresh_token for future refresh_token requests
        if (!array_key_exists('refresh_token', $tokenData)) {
            $tokenData['refresh_token'] = $accessToken->getRefreshToken();
        }
        // add the current DateTime as well to be able to figure out if the
        // token expired
        $tokenData['issued_at'] = $dateTime->format('Y-m-d H:i:s');

        return new self($tokenData);
    }

    public function getProviderId()
    {
        return $this->providerId;
    }

    /**
     * @return \DateTime
     */
    public function getIssuedAt()
    {
        return $this->issuedAt;
    }

    /**
     * @return string
     *
     * @see https://tools.ietf.org/html/rfc6749#section-5.1
     */
    public function getToken()
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
     * @return int|null
     *
     * @see https://tools.ietf.org/html/rfc6749#section-5.1
     */
    public function getExpiresIn()
    {
        return $this->expiresIn;
    }

    /**
     * @return string|null the refresh token
     *
     * @see https://tools.ietf.org/html/rfc6749#section-1.5
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return string|null
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @param \DateTime $dateTime
     *
     * @return bool
     */
    public function isExpired(DateTime $dateTime)
    {
        if (is_null($this->getExpiresIn())) {
            // if no expiry was indicated, assume it is valid
            return false;
        }

        // check to see if issuedAt + expiresIn > provided DateTime
        $issuedAt = clone $this->issuedAt; // XXX do we need to clone here?
        $expiresAt = date_add($issuedAt, new DateInterval(sprintf('PT%dS', $this->getExpiresIn())));

        return $dateTime >= $expiresAt;
    }

    /**
     * @param string $jsonString
     */
    public static function fromJson($jsonString)
    {
        $tokenData = json_decode($jsonString, true);
        if (is_null($tokenData) && JSON_ERROR_NONE !== json_last_error()) {
            $errorMsg = function_exists('json_last_error_msg') ? json_last_error_msg() : json_last_error();
            throw new AccessTokenException(sprintf('unable to decode JSON from storage: %s', $errorMsg));
        }

        return new self($tokenData);
    }

    /**
     * @return string
     */
    public function toJson()
    {
        return json_encode(
            [
                'provider_id' => $this->getProviderId(),
                'issued_at' => $this->issuedAt->format('Y-m-d H:i:s'),
                'access_token' => $this->getToken(),
                'token_type' => $this->getTokenType(),
                'expires_in' => $this->getExpiresIn(),
                'refresh_token' => $this->getRefreshToken(),
                'scope' => $this->getScope(),
            ]
        );
    }

    /**
     * @param string $providerId
     */
    private function setProviderId($providerId)
    {
        $this->providerId = $providerId;
    }

    /**
     * @param string $issuedAt
     */
    private function setIssuedAt($issuedAt)
    {
        self::requireString('expires_at', $issuedAt);
        if (1 !== preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$/', $issuedAt)) {
            throw new AccessTokenException('invalid "expires_at"');
        }
        $this->issuedAt = new DateTime($issuedAt);
    }

    /**
     * @param string $accessToken
     */
    private function setAccessToken($accessToken)
    {
        self::requireString('access_token', $accessToken);
        // access-token = 1*VSCHAR
        // VSCHAR       = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $accessToken)) {
            throw new AccessTokenException('invalid "access_token"');
        }
        $this->accessToken = $accessToken;
    }

    /**
     * @param string $tokenType
     */
    private function setTokenType($tokenType)
    {
        self::requireString('token_type', $tokenType);
        if ('bearer' !== $tokenType) {
            throw new AccessTokenException('unsupported "token_type"');
        }
        $this->tokenType = $tokenType;
    }

    /**
     * @param int|null $expiresIn
     */
    private function setExpiresIn($expiresIn)
    {
        if (!is_null($expiresIn)) {
            self::requireInt('expires_in', $expiresIn);
            if (0 >= $expiresIn) {
                throw new AccessTokenException('invalid "expires_in"');
            }
        }
        $this->expiresIn = $expiresIn;
    }

    /**
     * @param string|null $refreshToken
     */
    private function setRefreshToken($refreshToken)
    {
        if (!is_null($refreshToken)) {
            self::requireString('refresh_token', $refreshToken);
            // refresh-token = 1*VSCHAR
            // VSCHAR        = %x20-7E
            if (1 !== preg_match('/^[\x20-\x7E]+$/', $refreshToken)) {
                throw new AccessTokenException('invalid "refresh_token"');
            }
        }
        $this->refreshToken = $refreshToken;
    }

    /**
     * @param string|null $scope
     */
    private function setScope($scope)
    {
        if (!is_null($scope)) {
            self::requireString('scope', $scope);
            // scope       = scope-token *( SP scope-token )
            // scope-token = 1*NQCHAR
            // NQCHAR      = %x21 / %x23-5B / %x5D-7E
            foreach (explode(' ', $scope) as $scopeToken) {
                if (1 !== preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scopeToken)) {
                    throw new AccessTokenException('invalid "scope"');
                }
            }
        }
        $this->scope = $scope;
    }

    /**
     * @param string $k
     * @param string $v
     */
    private static function requireString($k, $v)
    {
        if (!is_string($v)) {
            throw new AccessTokenException(sprintf('"%s" must be string', $k));
        }
    }

    /**
     * @param string $k
     * @param int    $v
     */
    private static function requireInt($k, $v)
    {
        if (!is_int($v)) {
            throw new AccessTokenException(sprintf('"%s" must be int', $k));
        }
    }
}
