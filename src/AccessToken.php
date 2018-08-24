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

use DateInterval;
use DateTime;
use Exception;
use fkooman\OAuth\Client\Exception\AccessTokenException;
use RuntimeException;

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

    /** @var null|int */
    private $expiresIn = null;

    /** @var null|string */
    private $refreshToken = null;

    /** @var null|string */
    private $scope = null;

    /** @var null|string */
    private $idToken = null;

    /**
     * @param array $tokenData
     */
    public function __construct(array $tokenData)
    {
        $requiredKeys = ['provider_id', 'issued_at', 'access_token', 'token_type'];
        foreach ($requiredKeys as $requiredKey) {
            if (false === \array_key_exists($requiredKey, $tokenData)) {
                throw new AccessTokenException(\sprintf('missing key "%s"', $requiredKey));
            }
        }

        // set required keys
        $this->setProviderId($tokenData['provider_id']);
        $this->setIssuedAt($tokenData['issued_at']);
        $this->setAccessToken($tokenData['access_token']);
        $this->setTokenType($tokenData['token_type']);

        // set optional keys
        if (\array_key_exists('expires_in', $tokenData)) {
            $this->setExpiresIn($tokenData['expires_in']);
        }
        if (\array_key_exists('refresh_token', $tokenData)) {
            $this->setRefreshToken($tokenData['refresh_token']);
        }
        if (\array_key_exists('scope', $tokenData)) {
            $this->setScope($tokenData['scope']);
        }
        if (\array_key_exists('id_token', $tokenData)) {
            $this->setIdToken($tokenData['id_token']);
        }
    }

    /**
     * @param Provider  $provider
     * @param \DateTime $dateTime
     * @param array     $tokenData
     * @param string    $scope
     *
     * @return AccessToken
     */
    public static function fromCodeResponse(Provider $provider, DateTime $dateTime, array $tokenData, $scope)
    {
        $tokenData['provider_id'] = $provider->getProviderId();

        // if the scope was not part of the response, add the request scope,
        // because according to the RFC, if the scope is ommitted the requested
        // scope was granted!
        if (false === \array_key_exists('scope', $tokenData)) {
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
     *
     * @return AccessToken
     */
    public static function fromRefreshResponse(Provider $provider, DateTime $dateTime, array $tokenData, self $accessToken)
    {
        $tokenData['provider_id'] = $provider->getProviderId();

        // if the scope is not part of the response, add the request scope,
        // because according to the RFC, if the scope is ommitted the requested
        // scope was granted!
        if (false === \array_key_exists('scope', $tokenData)) {
            $tokenData['scope'] = $accessToken->getScope();
        }
        // if the refresh_token is not part of the response, we wil reuse the
        // existing refresh_token for future refresh_token requests
        if (false === \array_key_exists('refresh_token', $tokenData)) {
            $tokenData['refresh_token'] = $accessToken->getRefreshToken();
        }
        // add the current DateTime as well to be able to figure out if the
        // token expired
        $tokenData['issued_at'] = $dateTime->format('Y-m-d H:i:s');

        return new self($tokenData);
    }

    /**
     * @return string
     */
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
     * @param \DateTime $dateTime
     *
     * @return bool
     */
    public function isExpired(DateTime $dateTime)
    {
        if (null === $this->getExpiresIn()) {
            // if no expiry was indicated, assume it is valid
            return false;
        }

        // check to see if issuedAt + expiresIn > provided DateTime
        $expiresAt = clone $this->issuedAt;
        $expiresAt->add(new DateInterval(\sprintf('PT%dS', $this->getExpiresIn())));

        return $dateTime >= $expiresAt;
    }

    /**
     * @param string $jsonString
     *
     * @return AccessToken
     */
    public static function fromJson($jsonString)
    {
        $tokenData = \json_decode($jsonString, true);
        if (null === $tokenData && JSON_ERROR_NONE !== \json_last_error()) {
            $errorMsg = \function_exists('json_last_error_msg') ? \json_last_error_msg() : \json_last_error();
            throw new AccessTokenException(\sprintf('unable to decode JSON from storage: %s', $errorMsg));
        }

        return new self($tokenData);
    }

    /**
     * @return string
     */
    public function toJson()
    {
        $jsonData = [
                'provider_id' => $this->getProviderId(),
                'issued_at' => $this->issuedAt->format('Y-m-d H:i:s'),
                'access_token' => $this->getToken(),
                'token_type' => $this->getTokenType(),
                'expires_in' => $this->getExpiresIn(),
                'refresh_token' => $this->getRefreshToken(),
                'scope' => $this->getScope(),
        ];

        $jsonString = \json_encode($jsonData);
        if (false === $jsonString) {
            throw new RuntimeException('unable to encode JSON');
        }

        return $jsonString;
    }

    /**
     * @return null|string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * @param string $providerId
     *
     * @return void
     */
    private function setProviderId($providerId)
    {
        $this->providerId = $providerId;
    }

    /**
     * @param string $issuedAt
     *
     * @return void
     */
    private function setIssuedAt($issuedAt)
    {
        if (1 !== \preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$/', $issuedAt)) {
            throw new AccessTokenException('invalid "expires_at" (syntax)');
        }

        // make sure it is actually a valid date
        try {
            $this->issuedAt = new DateTime($issuedAt);
        } catch (Exception $e) {
            throw new AccessTokenException(
                \sprintf('invalid "expires_at": %s', $e->getMessage())
            );
        }
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
            throw new AccessTokenException('invalid "access_token"');
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
            throw new AccessTokenException('unsupported "token_type"');
        }
        $this->tokenType = $tokenType;
    }

    /**
     * @param null|mixed $expiresIn
     *
     * @return void
     */
    private function setExpiresIn($expiresIn)
    {
        if (null !== $expiresIn) {
            if (false === \is_int($expiresIn)) {
                throw new AccessTokenException('"expires_in" must be int');
            }
            if (0 >= $expiresIn) {
                throw new AccessTokenException('invalid "expires_in"');
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
                throw new AccessTokenException('invalid "refresh_token"');
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
                    throw new AccessTokenException('invalid "scope"');
                }
            }
        }
        $this->scope = $scope;
    }

    /**
     * @param null|string $idToken
     *
     * @return void
     */
    private function setIdToken($idToken)
    {
        $this->idToken = $idToken;
    }
}
