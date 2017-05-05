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

namespace fkooman\OAuth\Client;

use fkooman\OAuth\Client\Exception\SessionException;

class Session implements SessionInterface
{
    /**
     * @param string $key
     */
    public function get($key)
    {
        $this->startSession();
        if (!array_key_exists($key, $_SESSION)) {
            throw new SessionException(sprintf('key "%s" not found in session', $key));
        }

        return $_SESSION[$key];
    }

    /**
     * @param string $key
     * @param mixed  $value
     *
     * @return mixed
     */
    public function set($key, $value)
    {
        $this->startSession();
        $_SESSION[$key] = $value;
    }

    /**
     * @param string $key
     */
    public function del($key)
    {
        $this->startSession();
        if (!array_key_exists($key, $_SESSION)) {
            throw new SessionException(sprintf('key "%s" not found in session', $key));
        }
        unset($_SESSION[$key]);
    }

    private function startSession()
    {
        if ('' === session_id()) {
            session_start();
        }
    }
}
