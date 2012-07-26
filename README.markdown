# RProxy

RProxy is a reverse proxy server written with performance and scale in mind.

## Dependencies
* [Libevent](http://libevent.org)
* [Libevhtp](http://github.com/ellzey/libevhtp)
* [OpenSSL](http://openssl.org)
* [Libconfuse](http://www.nongnu.org/confuse/)

## Terminology

<table>
	<tr>
		<th>Name</th><th>Definition</th>
	</tr>
	<tr>
		<td>Downstream</td><td>The HTTP server or servers which sit behind RProxy</td>
	</tr>
	<tr>
		<td>Upstream</td><td>The HTTP client which makes request directly to the RProxy server</td>
	</tr>
	<tr>
		<td>vhost</td><td>Virtual hosts which are found via SNI or Host header value.</td>
	</tr>
	<tr>
		<td>HTTP Pipelining</td><td>A technique in which multiple requests can be sent to a single HTTP server connection.</td>
	</tr>
</table>

## Features

* HTTP pipelining to reduce connection overhead to a downstream (this reduces latency of a full handshake per-request to a downstream)
* Various methods of load-balancing client-requests to a downstream.
* Full SSL support: including TLS false start, x509 verification, certificate caching, session caching, and all commonly used SSL configuration options.
* Various X-Header configurations including options for added extended TLS fields.
* Upstream and downstream thresholding (to reduce memory for slow/blocking downstream connections)
* Per-downstream backlog, and backlog timeout  management.
* Virtual hosts.
* Rule based routing.
* Flexible logging configuration.
* Optional memory optimizations on systems which support mallopt() 
* Very low system footprint with optimal configurations.
* It's really @#$@#$r* fast. 

# Architecture
Each configured server contains one or more titled downstream configurations. These downstreams are globally accessable by every virtual host and the rules contained within. A virtual host is proceeded by a hostname, found either in a SSL SNI transaction, or via a 'Host' HTTP header value. Each of these virtual hosts contain one or more rules that match on a URI. Each of these rules can use one or more of the global downstreams to fulfill requests, these are referenced by the titles of the configured downstreams.

## Configuration
RProxy global configuration options are defined outside of other sub-directives:

		daemonize  = true
		rootdir    = /tmp
		user       = nobody
		group      = nobody
		max-nofile = 10000

* `daemonize`   if set to true, the server will run in the background. (default: false)
* `user`        user the server will run as
* `group`       group the server will run as
* `rootdir`     directory which RProxy will daemonize into.
* `max-nofile`  if your system supports set/getrlimits, this sets the maximum number of file-descriptors which can be open. It is suggested this be set to a very high number. (default: 100000).
** To adjust global limits, on OSX `sudo launchctl limit maxfiles 590000 590000`, on Linux: add `* hard nofile 590000` to your /etc/security/limits.conf

RProxy server configuration contains one or more `server` directives. Each of these
directives define how a single front-end proxy should behave. A basic server
configuration contains the following types of information:

* What address and port to bind to.
* How many listener threads to spawn.
* Optional SSL configuration directives.
* One or more Downstream configuration directives.
* Various upstream timeout settings.
* Various pending request configurations.

<pre>
	server {
		addr    = "127.0.0.1"
		port    = 443
		backlog = 1024
		threads = 4

		read-timeout    = { 60, 0 }
		write-timeout   = { 32, 0 }
		pending-timeout = { 10, 0 }
		max-pending     = 50

		downstream `X` {
			# see downstream configuration
		}

		ssl {
			# See SSL Configuration
		}

		vhost 'X' {
			# See vhost configuration
		}
	}
</pre>

* `addr` is the IP address to bind
* `port` is the TCP port to bind
* `backlog` is the backlog passed to listen()
* `threads` the number of request worker threads to spawn
* `read-timeout` { seconds, useconds } to wait for an Upstream connection to make a request.
* `write-timeout` { seconds, useconds } to wait for a blocking write to an Upstream connection.
* `pending-timeout` { seconds, useconds } to wait for a downstream connection to be available for a connection before a 503 is returned.
* `max-pending` the number of concurrent requests in a pending state.
* `ssl` parent SSL configuration (used if a vhost does not contain its own SSL configuration).

* `lb-method` the method which is used for load-balancing. The following methods are available 
	* `rtt` (default) based on prior requests, chooses a downstream connection from all configured downstreams with the lowest Round Trip Time.
	* `roundrobin` will send each request to a different configured downstream.
	* `most-idle` chooses the downstream with the most idle connections.
	* `none` simply chooses the first available connection it can find (no calculation of sorts).

### Downstream Configuration.

One or more downstreams can be configured. Each downstream can be referenced by any virtual host and their underlying rules. Each of the downstreams must be named in order for vhost rules to reference them.

Inside each downstream directive contains the following types of information:

* The IP address of the downstream server.
* The TCP Port of the downstream server.
* The number of connections to always maintain to support HTTP pipelining.
* Retry configuration which is used to reconnect to a downstream the proxy considers to be unavailable.
* Timeouts and Thresholding.


<pre>
	downstream {
		enabled        = true
		addr           = 127.0.0.1
		port           = 80
		connections    = 10
		high-watermark = 5242880
		read-timeout   = { 0, 0 }
		write-timeout  = { 2, 0 }
		retry          = { 0, 50000 }
	}
</pre>

* `addr` is the IP address of the Downstream.
* `port` is the TCP port of the Downstream.
* `connections` the number of connections to always keep established to the downstream.
* `high-watermark` if a downstream's write-buffer goes over this number, the upstream processing is paused until all data has been writen to the downstream. This helps with slow xfer to a downstream so that memory usage does not blow up. As soon as all data has been written, the upstream is resumed.
* `read-timeout` { seconds, useconds }  to wait for reading data from a downstream when an upstream request is made.
* `write-timeout` { seconds, useconds }  to wait for data to be written to a downstream when an upstream request is made.

In the above configuration, a single server instance will connect to "127.0.0.1" on port 80, with a max of 10 persistent connections. If 5242880 or more bytes of data is in the output socket buffer to the downstream, the upstream processing is paused until it is emptied.

When a downstream has been marked as down, this can mean one of serveral things; the downstream became unavailable, the upstream disconnected in the middle of a transaction (which RProxy must shut down both sides to funky state), any other socket error, or it takes more than 2 seconds to write **any** data to the downstream. In the above configuration, RProxy will attempt a reconnect in 0.50000 seconds if any of these conditions are met.

### Server SSL configuration

Each front-facing server configuration can be SSL enabled, which allows SSL operations to be offloaded at the proxy.

<pre>
	ssl {
		enabled = true
		cert    = server.crt
		key     = server.key
		ca			= /path/to/cafile
		capath	= /path/to/cadir
		ciphers = "RC4+RSA:HIGH:+MEDIUM:+LOW"

		protocols-on  = { TLS1 }
		protocols-off = { SSLv2, SSLv3 }

		verify-peer       = true
		enforce-peer-cert = true
		verify-depth      = 4
		context-timeout   = 172800

		cache-enabled = true
		cache-size    = 1024
		cache-timeout = 60
	}
</pre>

* `enabled` if set to true, SSL is enabled, otherwise SSL is disabled.
* `cert` the servers SSL cert
* `key` the servers private SSL key
* `ca` a specific CA file
* `capath` relative path to search for valid CA's
* `ciphers` accepted ciphers
* `protocols-(on|off)` the SSL options for enabling or disabling SSL specific protocols. Options: SSLv2, SSLv3, TLSv1, or ALL
* `verify-peer` enables peer verification
* `enforce-peer-cert` if true, a client is rejected if it does not supply a client certificate.
* `cache-enabled` turn on SSL cache
* `cache-size` maximum size of the SSL cache
* `cache-timeout` time in seconds to expire entires in the SSL cache
* `context-timeout` set timeout for (OpenSSL >= 1.0) session timeouts.

## Virtual Host Configuration

One or more virtual hosts configured. Each virtual host contains a list of rules to be matched against. This will match either a SSL SNI hostname, or the Host header value in a request. Having SNI support allows for each vhost to have its own ssl configuration directive as describe above.

One or more URI rewrite configurations must be defined in order to establish a mapping between upstream requests to a downstream request.

<pre>
	vhost "*.example.com" {
		aliases = { *.example.net, www.example.org }

		ssl {
			# See SSL configuration, now specific to this vhost
			# Note: this will override the global server SSL configuration.
		}

		logging {
			# See logging configuration.
		}

		if-uri-match "/static.match" {
			# See rule configuration.
		}

		if-uri-gmatch "/glob.match/*" {
			# See rule configuration.
		}

		if-uri-rmatch "^/(regex|ReGeX).*/match/$" {
			# See rule configuration.
		}
	}
</pre>

Each `vhost` must contain a title and an optional array of aliases. The title represents what hostname to match on. These can be wildcard names. In the above configuration any requests matching *.example.com, *.example.net, or www.example.org will pass and begin the rule matching process.


### Logging Configuration

Each vhost can be configured with different log types and formats. A format is a special string which represents a piece of data in a request. These special strings are encapsulated inside {}. All other non-defined characters will be treated as text to be included within the log.

Logging is broken out into two parts: `request` and `error`. The `request` configuration is for logging fully processed HTTP requests, while `error` configuration is for critical errors or half-finished requests. Both of these directives contain the same configuration syntax.

<pre>
	logging {
		request {
			enabled = true
			output  = "syslog:local0"
			format  = "{SRC} {PROXY} [{TS}] \"{METH} {URI} {PROTO}\" - {STATUS} - \"{REF}\" - \"{UA}\" - \"{HOST}\" {US_HDR}:'Accept-Encoding' - {DS_HDR}:'Content-Type'"
		}

		error {
			enabled = true
			output  = "file:./error.log"
			format  = "{SRC} {HOST} {URI}"
		}
	}
</pre>


<table>
  <tr>
    <th>Format String</th><th>Definition</th>
  </tr>
  <tr>
  </tr>
  <tr> <td>{SRC}</td><td>The clients IP address.</td> </tr>
  <tr> <td>{PROXY}</td><td>Downstream IP:PORT which was used to service the request.</td> </tr>
  <tr> <td>{TS}</td><td>Timestamp for when the request was serviced.</td> </tr>
  <tr> <td>{UA}</td><td>Clients User-Agent.</td> </tr>
  <tr> <td>{METH}</td><td>HTTP method</td> </tr>
  <tr> <td>{URI}</td><td>Full URI the client requested.</td> </tr>
  <tr> <td>{PROTO}</td><td>HTTP protocol</td> </tr>
  <tr> <td>{STATUS}</td><td>HTTP response status code</td> </tr>
  <tr> <td>{REF}</td><td>Clients Referrer</td> </tr>
  <tr> <td>{HOST}</td><td>The value of the Host header from the client</td> </tr>
  <tr> <td>{DS_SPORT}</td><td>The source port of the downstream connection</td> </tr>
  <tr> <td>{US_SPORT}</td><td>The source port of the upstream connection</td> </tr>
  <tr> <td>{US_HDR}:'header-name'</td><td>Display the value of the specified request header. Note the header-name must be encapsulated between single quotes.</td></tr>
  <tr> <td>{DS_HDR}:'header-name'</td><td>Display the value of the specified response header. Note the header-name must be encapsulated between single quotes.</td></tr>
</table>

### Rules

Each vhost must be configured with a set of rules which contain information of what requests go to where and other configuration options listed below.

<pre>
	if-uri-match "/specific.uri" {
		downstreams            = { ds1, ds2, ds3 }
		lb-method              = roundrobin
		upstream-read-timeout  = { 5, 0 }
		upstream-write-timeout = { 10, 0 }
		passthrough            = false
		allow-redirect         = false
	}

	if-uri-rmatch "^/regex.uri/$" {
		downstreams = { ds1, ds2 }
		lb-method   = rtt
	}

	if-uri-gmatch "/glob.uri/*" {
		downstreams = { ds1 }
		lb-method   = most-idle
	}
</pre>

#### Rule types

`if-uri-match` is a specific uri match, so "/blah" will *ONLY* match the URI "/blah" and nothing else.
`if-uri-rmatch` is a extended POSIX regex string.
`if-uri-gmatch` is a glob (wildcard) match.

#### Rule options

TBD

# Real world example.

<pre>

	server {
		addr    = 0.0.0.0
		port    = 443
		backlog = 1024 # listen backlog
		threads = 8    # spawn 8 listener threads.

		read-timeout    = { 30, 0 } # Drop upstream connection if idle for 30 seconds
		write-timeout   = { 5,  0 } # Drop upstream connection if write() hangs for 5 seconds
		pending-timeout = { 2,  0 } # Drop upstream connection if the request is in the pending
		                            # state (no downstreams available) for 2 seconds
		max-pending     = 50        # If the number of pending requests goes over 50, immediately drop.

		ssl {
			enabled           = true
			protocols-on      = { TLSv1, SSLv3 }
			protocols-off     = { SSLv3 }
			cert              = server.crt
			key               = server.key
			ca                = server.ca
			capath            = ./capath/
			ciphers           = "eNULL:RC4-SHA"
			enforce-peer-cert = false
			verify-peer       = false
			verify-depth      = 0
			cache-enabled     = true
			cache-timeout     = 1024
			cache-size        = 65535
			context-timeout   = 0
		}

		downstream downstream01 {
			enabled        = true
			addr           = backend.host01 # Can be hostname or IP
			port           = 80
			connections    = 10             # How many persistent connections.
			high-watermark = 50000
			read-timeout   = { 0, 0 }
			write-timeout  = { 0, 0 }
			retry          = { 0, 50000 }
		}

		downstream downstream02 {
			addr        = 127.0.0.1
			port        = 8080
			connections = 3
		}

		downstream downstream03 {
			addr        = localhost
			port        = 8081
		}

		vhost "ieatfood.net" {
			aliases = { www.ieatfood.net, ftp.ieatfood.net }

			ssl {
				enabled = true
				cert    = ieatfood.crt
				key     = ieatfood.key
			}

			logging {
				request {
					enabled = true
					output  = file:/dev/stdout
					format  = "{SRC} {HOST} {URI} {HOST}" 
				}

				error {
					enabled = true
					output  = file:/dev/stderr
				}
			}

			if-uri-gmatch "*" {
				downstreams = { downstream01, downstream02 }
				lb-method   = roundrobin
			}
	}

</pre>
				
			
