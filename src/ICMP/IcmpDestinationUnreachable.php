<?php

namespace gipfl\Protocol\ICMP;

class IcmpDestinationUnreachable extends IcmpPacket
{
    protected $type = 3;

    /**
     * Codes 0, 1, 4, and 5 may be received from a gateway.
     * Codes 2 and 3 may be received from a host.
     *
     * @var array
     */
    protected static $validCodes = array(
        0 => 'Destination network unreachable',
        1 => 'Destination host unreachable',
        2 => 'Destination protocol unreachable',
        3 => 'Destination port unreachable',
        4 => 'Fragmentation required, and DF flag set',
        5 => 'Source route failed',
        6 => 'Destination network unknown',
        7 => 'Destination host unknown',
        8 => 'Source host isolated',
        9 => 'Network administratively prohibited',
        10 => 'Host administratively prohibited',
        11 => 'Network unreachable for TOS',
        12 => 'Host unreachable for TOS',
        13 => 'Communication administratively prohibited',
        14 => 'Host Precedence Violation',
        15 => 'Precedence cutoff in effect',
    );

    protected $nextHopMtu;

    /** @var IcmpPacket */
    protected $originalPacket;

    public function getErrorMessage()
    {
        return self::$validCodes[$this->code];
    }

    /**
     * @return IcmpPacket
     */
    public function getOriginalPacket()
    {
        return $this->originalPacket;
    }

    /**
     * @param $payload
     * @return $this
     * @throws \Exception
     */
    public function parsePayload($payload)
    {
        // This is not correct, it could also be something not ICMP:
        $this->originalPacket = IcmpPacket::parse($payload);
        return $this;
    }

    public function parseHeaderFields($fields)
    {
        if ($this->code === 4) {
            $parts = \unpack('nunused/nnextmtu', $fields);
            $this->nextHopMtu = $parts['nextmtu'];
        }
    }
}
