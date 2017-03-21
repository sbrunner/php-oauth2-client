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

class SessionTokenStorage implements TokenStorageInterface
{
    /**
     * @param string $userId
     *
     * @return AccessToken|null
     */
    public function getAccessToken($userId)
    {
        // there is only one token ever in the session, it is bound to the
        // browser
        if (array_key_exists('access_token', $_SESSION)) {
            return $_SESSION['access_token'];
        }
    }

    public function updateAccessToken(AccessToken $accessToken)
    {
        $_SESSION['access_Token'] = $accessToken;
    }

    public function deleteAccessToken(AccessToken $accessToken)
    {
        unset($_SESSION['access_token']);
    }
}
