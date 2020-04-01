<?php namespace davelip\NTLM\Proxy;

class Gssapi
{
    private $ntlm_oid = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";

    private function makeoctstr($payload)
    {
        return $this->maketlv("\x04", $payload);
    }

    private function makeseq($payload)
    {
        return $this->maketlv("\x30", $payload);
    }

    private function maketlv($dertype, $payload)
    {
            if (strlen($payload)<128) {
            return $dertype . chr(strlen($payload)) . $payload;
        }
            if (strlen($payload)<256) {
            return $dertype . "\x81" . chr(strlen($payload)) . $payload;
        }
        #                >H
            return $dertype . "\x82" . pack("n",strlen($payload)) . $payload;
    }

    private function xrange($start, $limit, $step = 1) {
        if ($start <= $limit) {
            if ($step <= 0) {
                throw new LogicException('Step must be positive');
            }

            for ($i = $start; $i < $limit; $i += $step) {
                yield $i;
            }
        } else {
            if ($step >= 0) {
                throw new LogicException('Step must be negative');
            }

            for ($i = $start; $i > $limit; $i += $step) {
                yield $i;
            }
        }
    }

    private function parselen($berobj)
    {
#var_dump(__METHOD__);
        $length = ord(substr($berobj, 1, 1));
//var_dump("ord " . ord(substr($berobj, 1, 1)) . "\n");
//var_dump("length " . $length . "\n");

        # Short
        if ($length<128) {
//var_dump("parselen esco con length " . $length . "\n");
            return [$length, 2];
        }

        # Long
        $nlength = $length & 0x7F;
//var_dump("nlength " . $nlength . "\n");

        $length = 0;

        $generator = $this->xrange(2, 2+$nlength);
        foreach ($generator as $i) {
//var_dump('i ' . $i . "\n");
//var_dump("ord " . ord(substr($berobj, $i, 1)) . "\n");
            $length = $length*256 + ord(substr($berobj, $i, 1));
//var_dump("length " . $length . "\n");
        }

//var_dump("length " . $length . "\n");
//var_dump("nlength " . $nlength . "\n");
        return [$length, (2 + $nlength)];
    }

    private function  parsetlv($dertype, $derobj, $partial=false)
    {
#var_dump(__METHOD__);
#var_dump(base64_encode($derobj));
        if (substr($derobj, 0, 1)!=$dertype) {
            throw new Exception(printf('BER element %s does not start with type 0x%s.', bin2hex($derobj), bin2hex($dertype)));
        }

        $aOut = $this->parselen($derobj);
        $length = $aOut[0];
        $pstart = $aOut[1];

#printf("length = %d,  pstart = %d, pstart+length = %d", $length, $pstart, ($pstart+$length));
//var_dump($partial);

        if ($partial) {
            if (strlen($derobj)<$length+$pstart) {
                throw new Exception(printf('BER payload %s is shorter than expected (%d bytes, type %X).', bin2hex($derobj), $length, ord($derobj[0])));
            }
            return [substr($derobj, $pstart, $length), substr($derobj, $pstart+$length)];
        }
        if (strlen($derobj)!=($length+$pstart)) {
            throw new Exception(printf('BER payload %s is not %d bytes long (type %X).', bin2hex($derobj), $length, ord($derobj[0])));
        }
        $rv = substr($derobj, $pstart);
#printf("parsetlv rv %s", base64_encode($rv));
        return $rv;
    }

    private function parseoctstr($payload, $partial=false)
    {
#var_dump(__METHOD__);
        return $this->parsetlv("\x04", $payload, $partial);
    }

    private function parseint($payload, $partial=false, $tag="\x02")
    {
#var_dump(__METHOD__);
            $res = $this->parsetlv($tag, $payload, $partial);
            if ($partial) {
            $payload = $res[0];
        } else {
            $payload = $res;
        }
        $value = 0;

        // TODO
            //assert (ord(payload[0]) & 0x80) == 0x00

        $generator = $this->xrange(0, strlen($payload));
        foreach ($generator as $i) {
            $value = $value*256 + ord(substr($payload, $i, 1));
        }

            if ($partial) {
            return [$value, $res[1]];
        } else {
            return $value;
        }
    }


    private function parseenum($payload, $partial=false)
    {
#var_dump(__METHOD__);
            return $this->parseint($payload, $partial, "\x0A");
    }


    private function parseseq($payload, $partial=false)
    {
#var_dump(__METHOD__);
            return $this->parsetlv("\x30", $payload, $partial);
    }

    public function makeToken($ntlm_token, $type1=true)
    {
#var_dump(__METHOD__);
        if (! $type1) {
            $mechToken = $this->maketlv("\xa2", $this->makeoctstr($ntlm_token));
            $negTokenResp = $this->maketlv("\xa1", $this->makeseq($mechToken));
            return $negTokenResp;
        }

        # NegTokenInit (rfc4178)
        $mechlist = $this->makeseq($this->ntlm_oid);
        #var_dump(base64_encode($mechlist)); # VERIFIED
        $mechTypes = $this->maketlv("\xa0", $mechlist);
        #var_dump(base64_encode($mechTypes)); # VERIFIED
        $mechToken = $this->maketlv("\xa2", $this->makeoctstr($ntlm_token));
        #var_dump(base64_encode($mechToken)); #VERIFIED

        # NegotiationToken (rfc4178)
        $negTokenInit = $this->makeseq($mechTypes . $mechToken ); # + mechListMIC)
        #var_dump(base64_encode($negTokenInit));#VERIFIED
        $innerContextToken = $this->maketlv("\xa0", $negTokenInit);
        #var_dump(base64_encode($innerContextToken));#VERIFIED

        # MechType + innerContextToken (rfc2743)
        $thisMech = "\x06\x06\x2b\x06\x01\x05\x05\x02"; # SPNEGO OID 1.3.6.1.5.5.2
        #var_dump(base64_encode($thisMech));#VERIFIED
        $spnego = $thisMech . $innerContextToken;
        #var_dump(base64_encode($spnego));#VERIFIED

        # InitialContextToken (rfc2743)
        $msg = $this->maketlv("\x60", $spnego);
        #var_dump(base64_encode($msg));#VERIFIED
        return $msg;
    }

    public function extractToken($msg)
    {
#var_dump(__METHOD__);
        # Extract negTokenResp from NegotiationToken
//var_dump(base64_encode($msg));
        $msg = $this->parsetlv("\xa1", $msg, false);
//var_dump(base64_encode($msg));
        $spnego = $this->parseseq($msg);
#var_dump("spnego");
#var_dump(base64_encode($spnego));

        # Extract negState
        $aOut = $this->parsetlv("\xa0", $spnego, True);
        $negState = $aOut[0];
#var_dump("negState");
#var_dump(base64_encode($negState));
        $msg = $aOut[1];
#var_dump("msg");
#var_dump(base64_encode($msg));
        $status = $this->parseenum($negState);

        if ($status != 1) {
            throw new Exception(printf("Unexpected SPNEGO negotiation status (%d).", $status));
        }

        # Extract supportedMech
        $aOut = $this->parsetlv("\xa1", $msg, True);
        $supportedMech = $aOut[0];
        $msg = $aOut[1];
        if ($supportedMech!=$this->ntlm_oid) {
            throw new Exception("Unexpected SPNEGO mechanism in GSSAPI response.");
        }

        # Extract Challenge, and forget about the rest
        $aOut = $this->parsetlv("\xa2", $msg, True);
        $token = $aOut[0];
        $msg = $aOut[1];
        return $this->parseoctstr($token);
    }
}
