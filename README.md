# ntlm-proxy in pure PHP

Freely inspired by: 

* https://github.com/Legrandin/PyAuthenNTLM2
* https://github.com/loune/php-ntlm/


## Features

* Domain Controller support only (not LDAP);
* authenticate user credentials (not other checks);
* AD groups not supported.


## Installation

1. `$ git clone https://github.com/davelip/php-ntlm-proxy.git` # clone the repository
1. `$ cd php-ntlm-proxy` # enter directory
1. `$ composer install` # install dependendancies
1. `$ cp .env.example .env` # copy configuration file
1. `$ vim .env` # and insert your own configuration
1. `$ php server` # run the server

## Test

You can test the server connection in two ways (replace 8445 with the port you set in your configuration file):

`$ sudo netstat -plunt | grep 8445` 
If you see a row in the output your server is running

`$ telnet localhost 8445`
If you enter in interactive mode your server is running and you are communicating with him. Try to write something like `type1 123 AAAAA` and press Enter. You should get something like `Generic errorConnection closed by foreign host.`

For a production environment I suggest to install a tool like supervisord or to run php-ntlm-proxy like a system service (see next paragraphs).


### Supervisord

http://supervisord.org/

Install it and configure your server.


    [program:php-ntlm-proxy]
    command=/usr/bin/php server
    directory=/path/to/php-ntlm-proxy
    stderr_logfile=/var/log/supervisor/php-ntlm-proxy-stderr.log
    stdout_logfile=/var/log/supervisor/php-ntlm-proxy-stdout.log


### Running like a system service

https://maslosoft.com/blog/2019/07/10/running-php-script-as-a-system-service-in-ubuntu/


## Usage

When the server is correctly configured and up and running you can communicate with him throught socket to validate NTLM credentials.

See the php example in `example/auth.php`.


## Contribute

Contact me if you are interested.
