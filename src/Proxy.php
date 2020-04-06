<?php namespace davelip\NTLM\Proxy;

use davelip\NTLM\Proxy\Exception;
use davelip\NTLM\Proxy\Gssapi;

use Monolog\Logger;

class Proxy
{
    private $logger;
    private $socket;
    private $gssapi;
    private $userId = 0;

    private $sessionKey = "\x00\x00\x00\x00";

    const SMB_Header_Length               = 32;
    const SMB_COM_NEGOTIATE               = 0x72;
    const SMB_COM_SESSION_SETUP_ANDX      = 0x73;

    const SMB_FLAGS2_EXTENDED_SECURITY    = 0x0800;
    const SMB_FLAGS2_NT_STATUS            = 0x4000;
    const SMB_FLAGS2_UNICODE              = 0x8000;

    const CAP_UNICODE                     = 0x00000004;
    const CAP_NT_SMBS                     = 0x00000010;
    const CAP_STATUS32                    = 0x00000040;
    const CAP_EXTENDED_SECURITY           = 0x80000000;

    const NTLMSSP_NEGOTIATE_UNICODE       = 0x00000001;

    public function __construct(Logger $logger)
    {
        $this->session_id = session_id();

        $this->gssapi = new Gssapi();

        $this->socket = false;

        if ($this->socket == false) {
            $this->socket = socket_create(AF_INET, SOCK_STREAM, 0);
            if (!$this->socket) {
                throw new Exception("Unable to create socket to PDC");
                exit;
            }
            $bRv = socket_connect($this->socket, getenv('DC_IP'), getenv('DC_PORT'));
            if (!$bRv) {
                throw new Exception(sprintf("Unable to create stream to PDC (%s:%s)", getenv('DC_IP'), getenv('DC_PORT')));
                exit;
            }
            $timeout = array("sec"=>100,"usec"=>500000);

            socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, $timeout);

        }
    }

    public function __destruct()
    {
        if ($this->socket) {
            socket_close($this->socket);
        }
    }


    private function removeTransport($msg)
    {
        $data = substr($msg, 4);
        #                >H
        $length = @unpack('n', substr($msg, 2, 2))[1];
        if (substr($msg, 0, 2)!="\x00\x00" || $length!=strlen($data)) {
            throw new Exception(printf('Error while parsing Direct TCP transport Direct (%d, expected %d).', $length, strlen($data)));
        }
        return $data;
    }

    private function parseSessionSetupResp($resp)
    {
##var_dump(__METHOD__);
        $smb_data = $this->removeTransport($resp);
        $hdr = substr($smb_data, 0, self::SMB_Header_Length);
        $msg = substr($smb_data, self::SMB_Header_Length);

        # <I little-endian unsigned int
        $status = unpack('V', substr($hdr, 5, 4))[1];
        if ($status==0) {
            return [true, ''];
        }
        if ($status!=0xc0000016) {
            return [false, ''];
        }

        # User ID
        # <H little-endian unsigned short
        $this->userId = unpack('v', substr($hdr, 28, 2))[1];
        # WordCount
        $idx = 0;
        if ($msg[$idx]!="\x04") {
            throw new Exception('Incorrect WordCount');
        }
        # SecurityBlobLength
        $idx += 7;
        # <H little-endian unsigned short
        $length = unpack('v', substr($msg, $idx, 2))[1];
        # Security Blob
        $idx += 4;
        $blob = substr($msg, $idx, $length);
        $aRv =  [true, $this->gssapi->extractToken($blob)];
        return $aRv;
    }


    private function authenticate($ntlm_authenticate)
    {
        $msg = $this->makeSessionSetupRequest($ntlm_authenticate, false);
        $msg = $this->transaction($msg);
        return $this->parseSessionSetupResp($msg)[0];
    }

    public function handleType3($ntlm_message)
    {
        $result = false;

        $result = $this->authenticate($ntlm_message);

        return $result;
    }

    public function negotiate($data)
    {
        $msg = $this->makeNegotiateProtocolRequest();
        if ($msg) {
            $msg = $this->transaction($msg);
            // TODO
            //$this->parseNegotiateProtocolResp($msg);
        }

        $msg = $this->makeSessionSetupRequest($data, true);

        $resp = $this->transaction($msg);

        $aOut = $this->parseSessionSetupResp($resp);
        if (!$aOut[0]) {
            return false;
        }
        return $aOut[1];
    }

    private function getTransportLength($data)
    {
        #              >H
        return unpack("n", substr($data, 2, 2))[1];
    }

    public function transaction($msg)
    {
        if ($this->socket==false) {
            throw new Exception("Socket has gone away");
            exit;
        }
        $sent = socket_send($this->socket, $msg, strlen($msg), 0);
        $data = @socket_read($this->socket, 4);
        if ($data!==false) {
            $length = $this->getTransportLength($data);
            $data .= socket_read($this->socket, $length);
            # Response has three parts the first and the last are ever the same (if $msg is invariant) the central part always changes!
            # first: AAAAzf9TTUJyAAAAAIAAyAAAAAAAAAAAAAAAAAAAAAAAAAAAEQAADzIAAQAEQQAAAAABAAAAAAD88wGA
            # central: snitLlE
            # last: E1gHE/wCIAB6iHa+rO2hHlEuUDUTl7itgdgYGKwYBBQUCoGwwaqA8MDoGCisGAQQBgjcCAh4GCSqGSIL3EgECAgYJKoZIhvcSAQICBgoqhkiG9xIBAgIDBgorBgEEAYI3AgIKoyowKKAmGyRub3RfZGVmaW5lZF9pbl9SRkM0MTc4QHBsZWFzZV9pZ25vcmU=

        }
        return $data;
    }

    private function createSMBHeader($command)
    {
        # See 2.2.3.1 in [MS-CIFS]
        $hdr =  "\xFFSMB";
        $hdr .= chr($command);
        # <I little-endian unsigned int
        $hdr .= pack("V", 0);    # Status
        $hdr .= "\x00";           # Flags
        # <H little-endian unsigned short
        $hdr .= pack("v",       # Flags2
            self::SMB_FLAGS2_EXTENDED_SECURITY   |
            self::SMB_FLAGS2_NT_STATUS           |
            self::SMB_FLAGS2_UNICODE
            );
        # PID high, SecurityFeatures, Reserved, TID, PID low, UID, MUX ID
        # "<H8sHHHHH" little endian ushort 8char ushort ushort ushort ushort ushort
        $hdr .= pack("va8vvvvv", 0, "", 0, 0, 0, $this->userId, 0);
        return $hdr;
    }

    private function addTransport($msg)
    {
        # ">H" big endian unsigned short
            return "\x00\x00" . pack("n", strlen($msg)) . $msg;
    }

    private function makeNegotiateProtocolRequest()
    {
            $this->userId = 0;
        $hdr = $this->createSMBHeader(self::SMB_COM_NEGOTIATE);
        $params = "\x00";
        $dialects = "\x02NT LM 0.12\x00";
        $data = pack("v", strlen($dialects)) . $dialects;
        return $this->addTransport($hdr.$params.$data);
    }
    private function makeSessionSetupRequest($ntlm_token, $type1=true)
    {
        //$this->userId = 0;
        $hdr = $this->createSMBHeader(self::SMB_COM_SESSION_SETUP_ANDX);

        # Start building SMB_Data, excluding ByteCount
        $data = $this->gssapi->makeToken($ntlm_token, $type1);

        # See 2.2.4.53.1 in MS-CIFS and 2.2.4.6.1 in MS-SMB
        $params = "\x0C\xFF\x00";             # WordCount, AndXCommand, AndXReserved
        # AndXOffset, MaxBufferSize, MaxMpxCount,VcNumber, SessionKey
        # "<HHHH4s" little endian ushort ushort ushort 4char
        $params .= pack("vvvva4", 0, 1024, 2, 1, "\x00");

        # "<H" little endian ushort
        $params .= pack("v", strlen($data));     # SecurityBlobLength
        # "<I" little endian uint
        $params .= pack("V",0);              # Reserved
        # "<I" little endian uint
        $params .= pack("V",                # Capabilities
              self::CAP_UNICODE  |
              self::CAP_NT_SMBS  |
              self::CAP_STATUS32 |
              self::CAP_EXTENDED_SECURITY);

        if ((strlen($data)+strlen($params))%2==1) {
            $data .= "\x00";
        }
        $data .= iconv("UTF-8", "UTF-16LE", "Python\0");  # NativeOS
        $data .= iconv("UTF-8", "UTF-16LE", "Python\0");  # NativeLanMan

        # "<H" little endian unsigned short
        $rv = $this->addTransport($hdr.$params.pack("v", strlen($data)).$data);
        return $rv;
    }


    private function close()
    {
        socket_close($this->socket);
    }
}
