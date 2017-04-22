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

namespace fkooman\OAuth\Client\Http;

class Request
{
    /** @var string */
    private $requestMethod;

    /** @var string */
    private $requestUri;

    /** @var string */
    private $requestBody;

    /** @var array */
    private $requestHeaders;

    /**
     * @param int    $statusCode
     * @param string $responseBody
     */
    public function __construct($requestMethod, $requestUri, array $requestHeaders = [], $requestBody = null)
    {
        $this->requestMethod = $requestMethod;
        $this->requestUri = $requestUri;
        $this->requestBody = $requestBody;
        $this->requestHeaders = $requestHeaders;
    }

    public function __toString()
    {
        $fmtHdrs = '';
        foreach ($this->requestHeaders as $k => $v) {
            $fmtHdrs .= sprintf('%s: %s', $k, $v).PHP_EOL;
        }

        return implode(
            PHP_EOL,
            [
                $this->requestUri,
                $this->requestMethod,
                $fmtHdrs,
                '',
                $this->requestBody,
            ]
        );
    }

    public static function get($requestUri, array $requestHeaders = [])
    {
        return new self('GET', $requestUri, $requestHeaders);
    }

    public static function post($requestUri, array $postData = [], array $requestHeaders = [])
    {
        return new self(
            'POST',
            $requestUri,
            array_merge(
                $requestHeaders,
                ['Content-Type' => 'application/x-www-form-urlencoded']
            ),
            http_build_query($postData, '&')
        );
    }

    public function setHeader($key, $value)
    {
        $this->requestHeaders[$key] = $value;
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return $this->requestMethod;
    }

    /**
     * @return string
     */
    public function getUri()
    {
        return $this->requestUri;
    }

    /**
     * @return string
     */
    public function getBody()
    {
        return $this->requestBody;
    }

    /**
     * @return array
     */
    public function getHeaders()
    {
        return $this->requestHeaders;
    }

    /**
     * @return string|null
     */
    public function getHeader($key)
    {
        foreach ($this->requestHeaders as $k => $v) {
            if (strtoupper($key) === strtoupper($k)) {
                return $v;
            }
        }

        return null;
    }
}
