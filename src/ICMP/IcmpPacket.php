<?php

namespace gipfl\Protocol\ICMP;

use gipfl\Protocol\Exception\ProtocolError;
use gipfl\Protocol\IPv4\IPv4Header;
use InvalidArgumentException;
use function pack;
use function sprintf;
use function substr;
use function unpack;

abstract class IcmpPacket
{
    protected static $typeMap = [
        0 =>  'IcmpEchoReply',
        3 =>  'IcmpDestinationUnreachable',
        // 4 =>  'IcmpSourceQuench',
        8 =>  'IcmpEchoRequest',
        11 => 'IcmpTimeExceeded',
        // 12 => 'IcmpParameterProblem',
        // 13 => 'IcmpTimestamp',
        // 14 => 'IcmpTimestampReply',
        // 15 => 'IcmpInformationRequest',
        // 16 => 'IcmpInformationReply',
    ];

    protected $type;

    /** @var IPv4Header */
    protected $ipheader;

    protected static $validCodes = array();

    protected $code;

    /** @var float */
    protected $sendTime;

    /** @var float */
    protected $receiveTime;

    public function __construct($code = 0)
    {
        if (! array_key_exists($code, static::$validCodes)) {
            throw new InvalidArgumentException(
                sprintf('Got invalid ICMP code %d for type %d', $code, $this->type)
            );
        }
        $this->code = $code;
    }

    abstract public function getBody();

    abstract public function getHeadFields();

    public function dump()
    {
        $checksum = "\x00\x00"; // no checksum yet
        $data = $this->getBody();
        $typeCode = $this->getTypeCodeString();
        $headFields = $this->getHeadFields();
        $checksum = $this->checksum("$typeCode$checksum$headFields$data");

        return "$typeCode$checksum$headFields$data";
    }

    public function __toString()
    {
        return $this->dump();
    }

    protected function checksum($data)
    {
        $nibbles = unpack('n*', $data);
        $sum = array_sum($nibbles);

        while ($shifted = $sum >> 16) {
            $sum = $shifted + ($sum & 0xffff);
        }

        return pack('n*', ~$sum);
    }

    /**
     * @param int $code
     * @return static
     */
    public static function create($code = 0)
    {
        $class = get_called_class();
        return new $class($code);
    }

    public function getIpHeader()
    {
        return $this->ipheader;
    }

    /**
     * @param $time
     * @return $this
     */
    public function setSendTime($time)
    {
        $this->sendTime = $time;

        return $this;
    }

    /**
     * @param $time
     * @return $this
     */
    public function setReceiveTime($time)
    {
        $this->receiveTime = $time;

        return $this;
    }

    /**
     * @return array
     */
    public static function getValidCodes()
    {
        return self::$validCodes;
    }

    /**
     * @return float
     */
    public function getSendTime()
    {
        return $this->sendTime;
    }

    /**
     * @return float
     */
    public function getReceiveTime()
    {
        return $this->receiveTime;
    }

    abstract public function parsePayload($payload);

    abstract public function parseHeaderFields($fields);

    /**
     * @param $data
     * @param null $ipHeader
     * @return IcmpPacket
     * @throws ProtocolError
     */
    public static function parse($data, $ipHeader = null)
    {
        if ($ipHeader === null) {
            $ipHeader = Ipv4Header::parse($data);
            $offset = $ipHeader->getHeaderLength();
        } else {
            $offset = 0;
        }

        if ($ipHeader->getProtocol() !== 1) {
            throw new ProtocolError('ICMP expected, got protocol ' . $ipHeader->getProtocol());
        }

        $icmpHeader = substr($data, $offset, 4);
        $offset += 4;
        $parts = unpack('Ctype/Ccode/nchecksum', $icmpHeader);
        if (! isset(self::$typeMap[$parts['type']])) {
            throw new ProtocolError(
                sprintf('Got unsupported ICMP type %d', $parts['type'])
            );
        }
        // TODO: Validate checksum here
        $class = __NAMESPACE__ . '\\' . self::$typeMap[$parts['type']];

        /** @var IcmpPacket $obj */
        $obj = new $class($parts['code']);
        $obj->parseHeaderFields(substr($data, $offset, 4));
        $obj->ipheader = $ipHeader;
        $offset += 4;
        $obj->parsePayload(substr($data, $offset));
        //type(8), code(8), checksum(16), id(16), seq(16), data...

        return $obj;
    }

    private function getTypeCodeString()
    {
        return pack('C', $this->type) . pack('C', $this->code);
    }
}
