<?php

namespace gipfl\Protocol\ICMP;

use function pack;
use function strlen;
use function unpack;

class IcmpEchoRequest extends IcmpPacket
{
    protected $type = 8;

    protected static $validCodes = array(
        0 => 'Echo request'
    );

    protected $code = 0;

    protected $identifier;

    protected $sequenceNumber;

    protected $body = 'ServusFromIcinga';

    public function setSequenceNumber($seq)
    {
        $this->sequenceNumber = $seq & 0xffff;

        return $this;
    }

    public function setIdentifier($id)
    {
        $this->identifier = $id & 0xffff;

        return $this;
    }

    /**
     * @return mixed
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * @return mixed
     */
    public function getSequenceNumber()
    {
        return $this->sequenceNumber;
    }

    public function parsePayload($payload)
    {
        $this->body = $payload;

        return $this;
    }

    public function getHeadFields()
    {
        return pack('n', $this->identifier) . pack('n', $this->sequenceNumber);
    }

    public function setBody($body)
    {
        $this->body = $body;

        return $this;
    }

    public function getBody()
    {
        if (strlen($this->body) % 2) {
            return $this->body . "\x00";
        }

        return $this->body;
    }

    public function parseHeaderFields($fields)
    {
        $parts = unpack('nidentifier/nsequence', $fields);
        $this->identifier = $parts['identifier'];
        $this->sequenceNumber = $parts['sequence'];

        return $this;
    }
}
