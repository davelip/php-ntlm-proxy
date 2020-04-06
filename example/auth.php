<?php
#
# NTLM PROXY
#
# Script PHP to use in an NTLM authenticated environment
#
# This script communicate with user-agent and with ntlm-php-proxy throught socket
#
# If the user insert valid credential it can extract user, domain and workstation from the message
#

# ini_set("display_errors", 1);
# ini_set("error_reporting", E_ALL);

session_start();

// NTLM specs http://davenport.sourceforge.net/ntlm.html
if (empty($_SERVER["HTTP_AUTHORIZATION"]) && empty($_SERVER["REDIRECT_HTTP_AUTHORIZATION"])){
    header("HTTP/1.1 401 Unauthorized");
    header("WWW-Authenticate: NTLM");
    exit;
}

if (!empty($_SERVER["REDIRECT_HTTP_AUTHORIZATION"])) {
    $auth = $_SERVER["REDIRECT_HTTP_AUTHORIZATION"];
} else {
    $auth = $_SERVER["HTTP_AUTHORIZATION"];
}

if (substr($auth,0,5) == "NTLM ") {

    $host = "127.0.0.1"; # Set your server ip
    $port = 8445; # Set your port

    // Timeout
    set_time_limit(1000);

    $socket = socket_create(AF_INET, SOCK_STREAM, 0) or die("Could not create socket\n");
    $result = socket_connect($socket, $host, $port) or die("Could not connect toserver\n");

    $msg = base64_decode(substr($auth, 5));
    if (substr($msg, 0, 8) != "NTLMSSP\x00") {
        die("error header not recognized");
    }
    if ($msg[8] == "\x01") {
        $message = 'type1' . ' ' . session_id() . ' ' . base64_encode($msg);
        $message = base64_encode($message);

        socket_write($socket, $message, strlen($message)) or die("Could not send data to server\n");

        $challenge = socket_read($socket, 1024) or die("Could not read server response\n");
        socket_close($socket);

        header("HTTP/1.1 401 Unauthorized");
        header("WWW-Authenticate: NTLM ".trim($challenge));
        exit;
    }
    else if ($msg[8] == "\x03") {
        $message = 'type3' . ' ' . session_id() . ' ' . base64_encode($msg);
        $message = base64_encode($message);

        socket_write($socket, $message, strlen($message)) or die("Could not send data to server\n");

        $authenticated = socket_read($socket, 1024) or die("Could not read server response\n");
        socket_close($socket);

        $authenticated = base64_decode($authenticated);

        if ($authenticated == 'valid') {
            function get_msg_str($msg, $start, $unicode = true) {
                $len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
                $off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
                if ($unicode)
                    return str_replace("\0", "", substr($msg, $off, $len));
                else
                    return substr($msg, $off, $len);
            }
            $user = get_msg_str($msg, 36);
            $domain = get_msg_str($msg, 28);
            $workstation = get_msg_str($msg, 44);
            print "You are $user from $domain/$workstation";
        } else {
            print 'invalid';
        }
    }
}
