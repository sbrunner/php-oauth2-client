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

use RuntimeException;

class CurlHttpClient implements HttpClientInterface
{
    /** @var resource */
    private $curlChannel;

    /** @var bool */
    private $httpsOnly = true;

    /**
     * @param array $configData
     */
    public function __construct(array $configData = [])
    {
        if (array_key_exists('httpsOnly', $configData)) {
            $this->httpsOnly = (bool) $configData['httpsOnly'];
        }
        $this->curlInit();
    }

    public function __destruct()
    {
        curl_close($this->curlChannel);
    }

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function send(Request $request)
    {
        $curlOptions = [
            CURLOPT_CUSTOMREQUEST => $request->getMethod(),
            CURLOPT_URL => $request->getUri(),
        ];

        if (in_array($request->getMethod(), ['POST', 'PUT', 'PATCH'])) {
            $curlOptions[CURLOPT_POSTFIELDS] = $request->getBody();
        }

        return $this->exec($curlOptions, $request->getHeaders());
    }

    private function curlInit()
    {
        if (false === $this->curlChannel = curl_init()) {
            throw new RuntimeException('unable to create cURL channel');
        }
    }

    private function curlReset()
    {
        if (function_exists('curl_reset')) {
            curl_reset($this->curlChannel);
        } else {
            curl_close($this->curlChannel);
            $this->curlInit();
        }
    }

    /**
     * @param array $curlOptions
     * @param array $requestHeaders
     *
     * @return Response
     */
    private function exec(array $curlOptions, array $requestHeaders)
    {
        $headerList = [];

        $this->curlReset();

        $defaultCurlOptions = [
            CURLOPT_HEADER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => $this->httpsOnly ? CURLPROTO_HTTPS : CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_HEADERFUNCTION => function ($curlChannel, $headerData) use (&$headerList) {
                if (false !== strpos($headerData, ':')) {
                    list($key, $value) = explode(':', $headerData, 2);
                    $headerList[trim($key)] = trim($value);
                }

                return strlen($headerData);
            },
        ];

        if (0 !== count($requestHeaders)) {
            $curlRequestHeaders = [];
            foreach ($requestHeaders as $k => $v) {
                $curlRequestHeaders[] = sprintf('%s: %s', $k, $v);
            }
            $defaultCurlOptions[CURLOPT_HTTPHEADER] = $curlRequestHeaders;
        }

        if (false === curl_setopt_array($this->curlChannel, $curlOptions + $defaultCurlOptions)) {
            throw new RuntimeException('unable to set cURL options');
        }

        if (false === $responseData = curl_exec($this->curlChannel)) {
            throw new RuntimeException(
                sprintf(
                    'failure performing the HTTP request: "[%d] %s"',
                    curl_errno($this->curlChannel),
                    curl_error($this->curlChannel)
                )
            );
        }

        return new Response(
            curl_getinfo($this->curlChannel, CURLINFO_HTTP_CODE),
            $responseData,
            $headerList
        );
    }
}
