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

namespace fkooman\OAuth\Client\Http;

use RuntimeException;

class Response
{
    /** @var int */
    private $statusCode;

    /** @var string */
    private $responseBody;

    /** @var array */
    private $responseHeaders;

    /**
     * @param int    $statusCode
     * @param string $responseBody
     */
    public function __construct($statusCode, $responseBody, array $responseHeaders = [])
    {
        $this->statusCode = $statusCode;
        $this->responseBody = $responseBody;
        $this->responseHeaders = $responseHeaders;
    }

    public function __toString()
    {
        $fmtHdrs = '';
        foreach ($this->responseHeaders as $k => $v) {
            $fmtHdrs .= sprintf('%s: %s', $k, $v).PHP_EOL;
        }

        return implode(
            PHP_EOL,
            [
                $this->statusCode,
                '',
                $fmtHdrs,
                '',
                $this->responseBody,
            ]
        );
    }

    /**
     * @return int
     */
    public function getStatusCode()
    {
        return $this->statusCode;
    }

    /**
     * @return string
     */
    public function getBody()
    {
        return $this->responseBody;
    }

    /**
     * @return array
     */
    public function getHeaders()
    {
        return $this->responseHeaders;
    }

    /**
     * @return string|null
     */
    public function getHeader($key)
    {
        foreach ($this->responseHeaders as $k => $v) {
            if (strtoupper($key) === strtoupper($k)) {
                return $v;
            }
        }

        return null;
    }

    /**
     * @return mixed
     */
    public function json()
    {
        $decodedJson = json_decode($this->responseBody, true);
        if (is_null($decodedJson) && JSON_ERROR_NONE !== json_last_error()) {
            // XXX better exception!!!
            throw new RuntimeException('unable to decode JSON');
        }

        return $decodedJson;
    }

    /**
     * @return bool
     */
    public function isOkay()
    {
        return 200 <= $this->statusCode && 300 > $this->statusCode;
    }
}
