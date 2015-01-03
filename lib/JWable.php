<?php

namespace SpomkyLabs\JOSE;

trait JWable
{
    protected $protected_headers = array();
    protected $unprotected_headers = array();
    protected $payload = null;

    public function getProtectedHeader()
    {
        return $this->protected_headers;
    }

    public function getUnprotectedHeader()
    {
        return $this->unprotected_headers;
    }

    public function getPayload()
    {
        return $this->payload;
    }

    public function setProtectedHeader(array $values)
    {
        $this->protected_headers = $values;

        return $this;
    }

    public function setUnprotectedHeader(array $values)
    {
        $this->unprotected_headers = $values;

        return $this;
    }

    /**
     * @param string $key
     * @param string $value
     */
    public function setProtectedHeaderValue($key, $value)
    {
        $this->protected_headers[$key] = $value;

        return $this;
    }

    /**
 * @param string $key
 * @param string $value
 */
public function setUnprotectedHeaderValue($key, $value)
    {
        $this->unprotected_headers[$key] = $value;

        return $this;
    }

    public function setPayload($payload)
    {
        $this->payload = $payload;

        return $this;
    }
}
