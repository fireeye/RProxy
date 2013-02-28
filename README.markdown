# RProxy

RProxy is a reverse proxy server written with performance and scale in mind.

# Building and installing

## Dependencies
* [Libevent](http://libevent.org)
* [Libevhtp](http://github.com/ellzey/libevhtp)
* [OpenSSL](http://openssl.org)
* [Libconfuse](http://www.nongnu.org/confuse/)

## Building with all dependencies compiled and statically linked
1. cd build
2. cmake -DRPROXY_BUILD_DEPS:STRING=ON .. 
3. make

## Build using system-wide dependencies
1. cd build
2. cmake ..
3. make


# Configuration

## Base Configuration

Before any other sub-section of the configuration is processed, the following
options can be set.

    daemonize  = false
    rootdir    = /tmp
    user       = nobody
    group      = nobody
    max-nofile = 1024


* __daemonize__

    The value of this option is a boolean (either true or false). If the value
    is true, RProxy will daemonize after start, otherwise the server will run in the
    foreground.

* __rootdir__

    If RProxy is configured to daemonize, the service will daemonize into this
   i directory.

* __user__

    Drop permissions to this user once root operations have been executed.
    The default of this is to run as the current user.

* __group__

    Drop permissions to this group once root operations have been executed.
    The default of this is to run as the current group.

* __max-nofile__

    If your system supports set/get rlimits, this sets the maximum number of
    file-descriptors the server can use at one time. Since RProxy will attempt
    to keep all of the downstream connections alive, it is suggested that this 
    number be pretty high.

    It should be noted that by default, most systems won't allow a user to go
    over a static number (most of the time 1024) even with setrlimit. In this
    case, a user must perform system-wide configurations.

    On linux you can add the following to the file /etc/security/limits.conf:

        "* hard nofile 590000"

    Note a reboot is required for this setting to take effect.

    On OSX, the following command can be run 

        "sudo launchctl limit maxfiles 590000 590000"

## Base Server Configuration

RProxy configuration must contain one or more "server" configuration sections.
These sections contains all the required information to deal with an incoming
request. The base configuration for a server is as follows:

    addr            = 127.0.0.1
    port            = 8080
    threads         = 4
    read-timeout    = { 0, 0 }
    write-timeout   = { 0, 0 }
    pending-timeout = { 0, 0 }
    high-watermark  = 0
    max-pending     = 0
    backlog         = 0
    
* __addr__

    The IP address in which to listen on.

* __port__

    The port to listen on

* __threads__

    The number of threads to use for this server (note that downstream
    connections are multiplied by this number).

* __read-timeout__

    The timeout in { 'seconds', 'microseconds' } for a client connection who has
    not sent any data. For example, if the value of this was "{ 1, 0 }", if the
    client has not been active for 1 second, the connection is closed.

    Setting this will evade potential idle connection DoS attacks.

* __write-timeout__

    The timeout in { 'seconds', 'microseconds' } to wait for data to the client
    to be written. If a client is blocking on the read for this long, the
    connection is closed. 

* __pending-timeout__

    When a connection is first made to RProxy, it is not immediately processed,
    instead it is placed in a pending queue. Only when a downstream connection has
    become available for use does the client get serviced. If a downstream does not
    become available for this amount of time, the client connection is shut down and
    removed from the pending queue.

    This makes sure both the RProxy service and the downstream services are
    never overloaded.

* __max-pending__

    If there are this many clients waiting for a backend server to be available,
    the incoming connection will not be accepted.

    This setting assures that the server cannot be overloaded with too many
    connections.

* __high-watermark__

    In many cases, a downstream may write faster to the RProxy than it can to
    the client. If the client is unable to keep up with the speed the backend server
    is sending, you may experience very high memory consumption. This is called a
    fast-writer/slow-reader effect.
 
    If the number of bytes in the output buffer to the client goes over this
    number, RProxy will disable reading data from the backend until all data in the
    output queue to the client has been sent.


## Server::Downstream Configuration

Each server section contains one or more "downstreams" (in other words, a
backend service). Each downstream configuration directive is named, which is
referenced by a rule (discussed later).

The information contained within the downstream configuration is global to a
server; all virtual host and rule will use the downstream information contained
within each downstream section.

    downstream <NAME> {
        enabled        = true
        addr           = x.x.x.x
        port           = nnnn
        connections    = 4
        high-watermark = 0
        read-timeout   = { 0, 0 }
        write-timeout  = { 0, 0 }
        retry          = { 0, 500000 }
    }

* __NAME__

    Each downstream must have a unique name.

* __enabled__

    If this value is set to false, RProxy will not attempt to make connections
    or utilize this downstream in any of the rules.

* __addr__

    The FQDN or IP address of this downstream server.

* __port__

    The listening port of the downstream server.

* __connections__

    The number of connections RProxy will attempt to keep available. Note that
    this number is multiplied by the number of threads configured for the
    server. For example if you have 4 threads, and 2 connections, RProxy actually
    maintains 8 connections.

* __high-watermark__

    If number of bytes in the sendQ is over the value of this number (in bytes),
    further reading from the client is disabled until the sendQ has been emptied.

    This setting assures that backend servers will not be overloaded by clients.

* __read-timeout__

    If no data has been read from this downstream for this many { seconds,
    microseconds }, the connection is terminated.

* __write-timeout__

    If a write request takes over { seconds, microseconds } to happen, the
    connection is terminated.

* __retry__

    If one of the downstream connections has been terminated for some reason,
    this is the time in { seconds, microseconds } RProxy will wait until it tries to
    re-establish the connection.

## Server::SSL Configuration

When this configuration section is present and enabled, RProxy will treat
incoming connections as SSL.

    ssl {
        enabled           = false
        protocols-on      = { ALL }
        protocols-off     = { }
        cert              = bleh.crt
        key               = bleh.key
        ca                = blah.ca
        capath            = /capath/
        ciphers           = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:RC4-SHA:RC4-MD5:ECDHE-RSA-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:AES128-SHA"
        verify-peer       = false
        enforce-peer-cert = false
        verify-depth      = 0
        context-timeout   = 172800
        cache-enabled     = true
        cache-timeout     = 1024
        cache-size        = 65535
    }

* __enabled__

    If set to true, SSL is enabled, otherwise SSL is disabled.

* __cert__

    The servers SSL cert

* __key__

     The servers private SSL key

* __ca__
     A specific CA file

* __capath__
    Relative path to search for valid CA's

* __ciphers__

    Accepted ciphers

* __protocols-(on|off)__

    The SSL options for enabling or disabling SSL specific protocols. Options: SSLv2, SSLv3, TLSv1, or ALL

* __verify-peer__

    Enables SSL client peer verification

* __enforce-peer-cert__

    If true, a client is rejected if it does not supply a client certificate.

* __cache-enabled__

    Enable SSL certificate cache

* __cache-size__

    Maximum size of the SSL cache 

* __cache-timeout__

    The lifetime a cert will be kept in the cache.

* __context-timeout__

    Timeout for (OpenSSL >= 1.0) session timeouts.

## Server::Vhost Configuration

## Server::Vhost::Rule Configuration

## Server::Logging Configuration
