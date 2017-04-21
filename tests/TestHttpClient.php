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
