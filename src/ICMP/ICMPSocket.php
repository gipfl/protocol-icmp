<?php

namespace gipfl\Protocol\ICMP;

use Exception;
use gipfl\Protocol\Exception\ProtocolError;
use function is_resource;
use function microtime;
use function socket_bind;
use function socket_create;
use function socket_getsockname;
use function socket_last_error;
use function socket_recvfrom;
use function socket_select;
use function socket_set_option;
use function socket_strerror;
use function sprintf;

class ICMPSocket
{
    protected $localIp;

    protected $socket;

    public function __construct($localIp = '0.0.0.0')
    {
        $this->localIp = $localIp;
    }

    /**
     * @return resource
     * @throws ProtocolError
     */
    public function getSocket()
    {
        if ($this->socket === null) {
            $this->socket = static::createRawIcmpSocket($this->localIp);
        }

        return $this->socket;
    }

    /**
     * @param IcmpPacket $packet
     * @param $destinationHost
     * @return $this
     * @throws ProtocolError
     */
    public function send(IcmpPacket $packet, $destinationHost)
    {
        $packet->setSendTime(microtime(true));
        $this->sendTo($destinationHost, (string) $packet);

        return $this;
    }

    /**
     * @return array
     * @throws ProtocolError
     */
    public function readPackets()
    {
        return $this->readPendingResponses();
    }

    /**
     * @param $host
     * @param $data
     * @return int
     * @throws ProtocolError
     */
    protected function sendTo($host, $data)
    {
        return \socket_sendto($this->getSocket(), $data, \strlen($data), 0, $host, 0);
    }

    /**
     * @return array
     * @throws ProtocolError
     */
    protected function readPendingResponses()
    {
        $write = [];
        $result = [];
        $socket = $this->getSocket();

        while (true) {
            $read = [$socket];
            $expect = [];
            // $changed = socket_select($read, $write, $expect, 0, 150000);
            if (empty($result)) {
                $changed = socket_select($read, $write, $expect, 3);
            } else {
                $changed = socket_select($read, $write, $expect, 0);
            }
            if ($changed === null) {
                throw new ProtocolError('Cannot read from ICMP socket');
            }
            if ($changed === 0) {
                break;
            }

            if (is_resource($socket)) { // Stupid but may help when stressed
                if ($packet = $this->readPacketFromPeer()) {
                    $result[] = $packet;
                } else {
                    \usleep(5000);
                }
            }
        }

        return $result;
    }

    /**
     * @return bool|IcmpPacket
     * @throws ProtocolError
     */
    protected function readPacketFromPeer()
    {
        // TODO: Buffer, deal with half-finished packets?
        $ip = $port = null;
        $socket = $this->getSocket();

        $now = microtime(true);
        $size = @socket_recvfrom($socket, $ret, 65535, 0, $ip, $port);
        if (! $size) {
            return false;
        }

        try {
            $packet = IcmpPacket::parse($ret);
            $packet->setReceiveTime($now);
        } catch (Exception $e) {
            echo $e->getMessage();
            return false;
        }

        if ($ret === false) {
            throw new ProtocolError(sprintf(
                'Cannot read from peer: %s',
                socket_strerror(socket_last_error($socket))
            ));
        }

        return $packet;
    }

    /**
     * @param string $localIp
     * @return resource
     * @throws ProtocolError
     */
    public static function createRawIcmpSocket($localIp = '0.0.0.0')
    {
        $socket = socket_create(AF_INET, SOCK_RAW, getprotobyname('ICMP'));
        socket_bind($socket, $localIp);
        if (! socket_getsockname($socket, $localIp)) {
            // TODO: detailed error, mention required capability
            throw new ProtocolError('Could not prepare local ICMP socket');
        }

        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array(
            'sec'  => 0,
            //'usec' => 100000
            'usec' => 1000
        ));

        return $socket;
    }
}
