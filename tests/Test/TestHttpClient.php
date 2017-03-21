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

namespace fkooman\OAuth\Client\Test;

use fkooman\OAuth\Client\Http\HttpClientInterface;
use fkooman\OAuth\Client\Http\Response;
use RuntimeException;

class TestHttpClient implements HttpClientInterface
{
    public function get($requestUri, array $requestHeaders = [])
    {
    }

    public function post($requestUri, array $postData = [], array $requestHeaders = [])
    {
        if ('authorization_code' === $postData['grant_type']) {
            if ('code12345' === $postData['code']) {
                return new Response(
                    200,
                    json_encode(
                        [
                            'access_token' => 'AT:code12345',
                            'token_type' => 'bearer',
                            'refresh_token' => 'refresh:x:y:z',
                        ]
                    )
                );
            }

            if ('code12345expires' === $postData['code']) {
                return new Response(
                    200,
                    json_encode(
                        [
                            'access_token' => 'AT:code12345expires',
                            'token_type' => 'bearer',
                            'expires_in' => 3600,
                            'refresh_token' => 'RT:code12345expires',
                        ]
                    )
                );
            }

            if ('invalid_code' === $postData['code']) {
                return new Response(
                    400,
                    json_encode(
                        [
                            'error' => 'invalid_grant',
                            'error_description' => 'invalid authorization code',
                        ]
                    )
                );
            }

            throw new RuntimeException('invalid code in unit test');
        }

        if ('refresh_token' === $postData['grant_type']) {
            return new Response(
                200,
                json_encode(
                    [
                        'access_token' => 'AT:refreshed',
                        'token_type' => 'bearer',
                        'expires_in' => 3600,
                    ]
                )
            );
        }

        throw new RuntimeException('invalid grant_type in unit test');
    }
}
