<?php

namespace gipfl\Protocol\ICMP;

use function unpack;

/**
 * Time Exceeded is sent when a gateway finds zero TTL in a packet
 */
class ICMPTimeExceeded extends IcmpPacket
{
    protected $type = 11;

    /**
     * Codes 0, 1, 4, and 5 may be received from a gateway.
     * Codes 2 and 3 may be received from a host.
     *
     * @var array
     */
    protected static $validCodes = [
        0 => 'Time to live exceeded in transit',
        1 => 'Fragment reassembly time exceeded',
    ];

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

    public function parsePayload($payload)
    {
        // This is not correct, it could also be something not ICMP:
        $this->originalPacket = IcmpPacket::parse($payload);
        return $this;
    }

    public function parseHeaderFields($fields)
    {
        if ($this->code === 4) {
            $parts = unpack('nunused/nnextmtu', $fields);
            $this->nextHopMtu = $parts['nextmtu'];
        }
    }
}
