<?php namespace davelip\NTLM\Proxy;

use davelip\NTLM\Proxy\Gssapi;

class Proxy
{
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

    public function __construct()
    {
        $this->session_id = session_id();

        $this->gssapi = new Gssapi();

        $this->socket = false;
/*
        if ($this->cache->exists('staminkia' . $this->session_id)!=0) {
var_dump('prendo in cache');
            $this->socket = $this->cache->get('staminkia' . $this->session_id);
        }
*/

        if ($this->socket == false) {
            $this->socket = socket_create(AF_INET, SOCK_STREAM, 0);
            if (!$this->socket) {
                throw new Exception("Unable to create socket to PDC");
                exit;
            }
            $bRv = socket_connect($this->socket, "192.168.1.7", 445);
            if (!$bRv) {
                throw new Exception("Unable to create stream to PDC");
                exit;
            }
            $timeout = array("sec"=>100,"usec"=>500000);
            socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, $timeout);

        }
    }

    public function __destruct()
    {
        if ($this->socket) {
            $this->socket->close();
        }
    }


    private function removeTransport($msg)
    {
        $data = substr($msg, 4);
        #                >H
        $length = unpack('n', substr($msg, 2, 2))[1];
        if (substr($msg, 0, 2)!="\x00\x00" || $length!=strlen($data)) {
            throw new Exception(printf('Error while parsing Direct TCP transport Direct (%d, expected %d).', $length, strlen($data)));
        }
        return $data;
    }

    private function parseSessionSetupResp($resp)
    {
##var_dump(__METHOD__);
        $smb_data = $this->removeTransport($resp);
##var_dump('smb_data ' . base64_encode($smb_data));
        $hdr = substr($smb_data, 0, self::SMB_Header_Length);
#var_dump('hdr ' . base64_encode($hdr));
        $msg = substr($smb_data, self::SMB_Header_Length);
#var_dump('msg ' . base64_encode($msg));

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
#var_dump('userId ' . $this->userId); #VERIFIED
        # WordCount
        $idx = 0;
        if ($msg[$idx]!="\x04") {
            throw new Exception('Incorrect WordCount');
        }
        # SecurityBlobLength
        $idx += 7;
        # <H little-endian unsigned short
        $length = unpack('v', substr($msg, $idx, 2))[1];
#var_dump('length ' . $length); #VERIFIED
        # Security Blob
        $idx += 4;
#var_dump('idx ' . $idx);
#var_dump('idx+length ' . ($idx+$length));
        $blob = substr($msg, $idx, $length);
#var_dump('blob ' . base64_encode($blob));
        $aRv =  [true, $this->gssapi->extractToken($blob)];
#var_dump('token ' . base64_encode($aRv));
        return $aRv;
    }


    private function authenticate($ntlm_authenticate)
    {
        $msg = $this->makeSessionSetupRequest($ntlm_authenticate, false);
#var_dump('PD');
        $msg = $this->transaction($msg);
        return $this->parseSessionSetupResp($msg)[0];
    }

    public function handleType3($ntlm_message)
    {
            $result = $this->authenticate($ntlm_message);
#var_dump($result);
        die();
            #except Exception, e:
                #req.log_error('PYNTLM: Error when retrieving Type 3 message from server = %s' % str(e), apache.APLOG_CRIT)
                #user, domain = 'invalid', 'invalid'
                #result = False
            #if not result:
                #cache.remove(req.connection.id)
                #req.log_error('PYNTLM: User %s/%s authentication for URI %s' % (
                        #domain,user,req.unparsed_uri))
                #return handle_unauthorized(req)

        #req.log_error('PYNTLM: User %s/%s has been authenticated to access URI %s' % (user,domain,req.unparsed_uri), apache.APLOG_NOTICE)
        #set_remote_user(req, user, domain)
        #result = check_authorization(req, user, proxy)
        #cache.remove(req.connection.id)

            #if not result:
                #return apache.HTTP_FORBIDDEN

            #req.connection.notes.add('NTLM_AUTHORIZED',req.user)
            #return apache.OK
    }

    public function negotiate($data)
    {
        $msg = $this->makeNegotiateProtocolRequest();
        #var_dump(base64_encode($msg)); #VERIFIED
        if ($msg) {
            $msg = $this->transaction($msg);
            #var_dump(base64_encode($msg)); #VERIFIED
            // TODO
            //$this->parseNegotiateProtocolResp($msg);
        }

        #var_dump(base64_encode($data)); #VERIFIED
        $msg = $this->makeSessionSetupRequest($data, true);
        #var_dump(base64_encode($msg)); #VERIFIED

        $resp = $this->transaction($msg);
        //var_dump(base64_encode($resp));

        $aOut = $this->parseSessionSetupResp($resp);
#var_dump('aOut');
#var_dump($aOut);
#die();
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
//var_dump('transaction msg b64 ' . base64_encode($msg));
//var_dump('transaction msg len' . strlen($msg));
        $sent = socket_send($this->socket, $msg, strlen($msg), 0);
        $data = socket_read($this->socket, 4);
//var_dump('transaction data4 b64 ' . base64_encode($data));
        if ($data!==false) {
            $length = $this->getTransportLength($data);
//var_dump('getTransportLength length ' . $length);
            $data .= socket_read($this->socket, $length);
            # Response has three parts the first and the last are ever the same (if $msg is invariant) the central part always changes!
            # first: AAAAzf9TTUJyAAAAAIAAyAAAAAAAAAAAAAAAAAAAAAAAAAAAEQAADzIAAQAEQQAAAAABAAAAAAD88wGA
            # central: snitLlE
            # last: E1gHE/wCIAB6iHa+rO2hHlEuUDUTl7itgdgYGKwYBBQUCoGwwaqA8MDoGCisGAQQBgjcCAh4GCSqGSIL3EgECAgYJKoZIhvcSAQICBgoqhkiG9xIBAgIDBgorBgEEAYI3AgIKoyowKKAmGyRub3RfZGVmaW5lZF9pbl9SRkM0MTc4QHBsZWFzZV9pZ25vcmU=

        }
#var_dump('transaction data b64' . base64_encode($data));
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
        #var_Dump(base64_encode($hdr)); # VERIFIED

        # Start building SMB_Data, excluding ByteCount
        $data = $this->gssapi->makeToken($ntlm_token, $type1);
        #var_dump(base64_encode($data)); #VERIFIED

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
        #var_Dump(base64_encode($params)); # VERIFIED

        if ((strlen($data)+strlen($params))%2==1) {
            $data .= "\x00";
        }
        $data .= iconv("UTF-8", "UTF-16LE", "Python\0");  # NativeOS
        $data .= iconv("UTF-8", "UTF-16LE", "Python\0");  # NativeLanMan
        #var_Dump(base64_encode($data)); #VERIFIED
        #var_Dump(strlen($data)); #VERIFIED

        # "<H" little endian unsigned short
        $rv = $this->addTransport($hdr.$params.pack("v", strlen($data)).$data);
        #var_Dump(base64_encode($rv));#VERIFIED
        return $rv;
    }


    private function close()
    {
        socket_close($this->socket);
    }
}
