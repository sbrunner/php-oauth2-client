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

namespace fkooman\OAuth\Client\Tests;

use fkooman\OAuth\Client\Http\HttpClientInterface;
use fkooman\OAuth\Client\Http\Response;

class TestHttpClient implements HttpClientInterface
{
    public function get($requestUri, array $requestHeaders = [])
    {
        if ('https://example.org/resource' === $requestUri) {
            if (array_key_exists('Authorization', $requestHeaders)) {
                if ('Bearer AT:xyz' === $requestHeaders['Authorization']) {
                    return new Response(
                        200,
                        json_encode(['ok' => true])
                    );
                }
                if ('Bearer AT:refreshed' === $requestHeaders['Authorization']) {
                    return new Response(
                        200,
                        json_encode(['refreshed' => true])
                    );
                }

                return new Response(
                    400,
                    json_encode(['error' => 'invalid_token']),
                    [
                        'Content-Type' => 'application/json',
                        'WWW-Authentication' => 'Bearer error="invalid_token"',
                    ]
                );
            }
        }

        return new Response(
            404,
            'NOT FOUND',
            [
                'Content-Type' => 'text/plain',
            ]
        );
    }

    public function post($requestUri, array $postData = [], array $requestHeaders = [])
    {
        if ('http://localhost/token' === $requestUri) {
            // interacting with token endpoint
            if ('refresh_token' === $postData['grant_type']) {
                if ('RT:abc' === $postData['refresh_token']) {
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

                return new Response(
                    400,
                    json_encode(['error' => 'invalid_grant', 'error_description' => 'invalid refresh_token'])
                );
            }

            if ('authorization_code' === $postData['grant_type']) {
                if ('AC:abc' === $postData['code']) {
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

                return new Response(
                    400,
                    json_encode(['error' => 'invalid_grant', 'error_description' => 'invalid authorization_code'])
                );
            }

            return new Response(
                400,
                json_encode(['error' => 'unsupported_grant_type'])
            );
        }

        return new Response(
            404,
            'NOT FOUND',
            [
                'Content-Type' => 'text/plain',
            ]
        );
    }
}
