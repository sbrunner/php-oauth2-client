<?php
/**
 *  Copyright (C) 2017 François Kooman <fkooman@tuxed.net>.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace fkooman\OAuth\Client;

use DateTime;

/**
 * AccessToken object containing the response from the OAuth 2.0 provider's
 * token response.
 */
class AccessToken
{
    /** @var string */
    private $token;

    /** @var string */
    private $tokenType;

    /** @var string */
    private $scope;

    /** @var \DateTime */
    private $expiresAt;

    public function __construct($token, $tokenType, $scope, DateTime $expiresAt)
    {
        $this->token = $token;
        $this->tokenType = $tokenType;
        $this->scope = $scope;
        $this->expiresAt = $expiresAt;
    }

    /**
     * Get the access token as string.
     *
     * @return string the access token
     */
    public function __toString()
    {
        return sprintf(
            'token_type: %s, scope: %s, expires_at: %s, token: %s',
            $this->getTokenType(),
            $this->getScope(),
            $this->getExpiresAt()->format('Y-m-d H:i:s'),
            $this->getToken()
        );
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
        return $this->token;
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
     * @return DateTime
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }
}
