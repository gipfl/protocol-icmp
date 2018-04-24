<?php

namespace gipfl\Protocol\ICMP;

class IcmpEchoReply extends IcmpPacket
{
    protected $type = 0;

    protected $identifier;

    protected $sequenceNumber;

    protected static $validCodes = array(
        0 => 'Echo reply'
    );

    public function parsePayload($payload)
    {
        // $head = unpack('Nidentifier/Nsequence', substr($payload, 0, 4));
        // var_dump($head);
    }

    public function getIdentifier()
    {
        return $this->identifier;
    }

    public function getSequenceNumber()
    {
        return $this->sequenceNumber;
    }

    public function parseHeaderFields($fields)
    {
        $parts = \unpack('nidentifier/nsequence', $fields);
        $this->identifier = $parts['identifier'];
        $this->sequenceNumber = $parts['sequence'];

        return $this;
    }
}
