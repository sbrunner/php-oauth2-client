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

use fkooman\OAuth\Client\Exception\IdTokenException;
use RuntimeException;

class IdToken
{
    /** @var object */
    private $jsonObj;

    /**
     * @param string $jwtStr
     */
    public function __construct($jwtStr)
    {
        $jwtParts = \explode('.', $jwtStr);
        if (3 !== \count($jwtParts)) {
            throw new IdTokenException('invalid JWT token');
        }

        // we do NOT need to verify the JWT signature as the ID Token is
        // obtained through the "Authorization Code Flow", see e.g.
        // https://openid.net/specs/openid-connect-basic-1_0.html
        $jsonObj = \json_decode($jwtParts[1]);
        if (null === $jsonObj) {
            if (JSON_ERROR_NONE !== \json_last_error()) {
                throw new RuntimeException('JSON: decode error');
            }
        }
        if (!\is_object($jsonObj)) {
            throw new RuntimeException('JSON: not a JSON object');
        }
        $this->jsonObj = $jsonObj;
    }

    /**
     * @return string
     */
    public function getIss()
    {
        return $this->requireStringProperty('iss');
    }

    /**
     * @return string
     */
    public function getSub()
    {
        return $this->requireStringProperty('sub');
    }

    /**
     * @return string
     */
    public function getAud()
    {
        return $this->requireStringProperty('aud');
    }

    /**
     * @return int
     */
    public function getExp()
    {
        return $this->requireIntProperty('exp');
    }

    /**
     * @return int
     */
    public function getIat()
    {
        return $this->requireIntProperty('iat');
    }

    /**
     * @param string $propertyName
     *
     * @return string
     */
    private function requireStringProperty($propertyName)
    {
        $this->requireProperty($propertyName);
        if (!\is_string($this->jsonObj->$propertyName)) {
            throw new IdTokenException(\sprintf('property "%s" not a string', $propertyName));
        }

        return $this->jsonObj->$propertyName;
    }

    /**
     * @param string $propertyName
     *
     * @return int
     */
    private function requireIntProperty($propertyName)
    {
        $this->requireProperty($propertyName);
        if (!\is_int($this->jsonObj->$propertyName)) {
            throw new IdTokenException(\sprintf('property "%s" not an int', $propertyName));
        }

        return $this->jsonObj->$propertyName;
    }

    /**
     * @param string $propertyName
     *
     * @return void
     */
    private function requireProperty($propertyName)
    {
        if (!\property_exists($this->jsonObj, $propertyName)) {
            throw new IdTokenException(\sprintf('missing property "%s"', $propertyName));
        }
    }
}
