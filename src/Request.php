<?php namespace davelip\NTLM\Proxy;

class Request
{
    /**
     * The request type
     *
     * @var string
     */
    protected $type = null;

    /**
     * The requested session_id
     *
     * @var string
     */
    protected $session_id = null;

    /**
     * The request param
     *
     * @var string
     */
    protected $param = null;

    /**
     * Create new request instance using a string
     *
     * @param string            $message
     * @return Request
     */
    public static function withString($message)
    {
        //$lines = explode( "\n", $message);

        $aOut = explode(' ', $message);

	$type = isset($aOut[0]) ? $aOut[0] : null;
	$session_id = isset($aOut[1]) ? $aOut[1] : null;
	$param = isset($aOut[2]) ? $aOut[2] : null;

        // create new request object
        return new static($type, $session_id, $param);
    }

    /**
     * Request constructor
     *
     * @param string            $type
     * @param string            $session_id
     * @param array             $param
     * @return void
     */
    public function __construct($type, $session_id, $param)
    {
        $this->type = $type;
        $this->session_id = $session_id;
        $this->param = $param;
    }

    /**
     * Return the request type
     *
     * @return string
     */
    public function type()
    {
        return $this->type;
    }

    /**
     * Return the request session_id
     *
     * @return string
     */
    public function sessionId()
    {
        return $this->session_id;
    }

    /**
     * Return a request param
     *
     * @return string
     */
    public function param()
    {
        return $this->param;
    }
}
