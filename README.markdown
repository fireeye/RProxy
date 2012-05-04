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
		<td>Rewrite</td><td>A URI which is translated from a client URI and transformed into another URI sent to ta Downstream</td>
	</tr>
	<tr>
		<td>HTTP Pipelining</td><td>A technique in which multiple requests can be sent to a single HTTP server connection.</td>
	</tr>
</table>

## Features

* HTTP pipelining to reduce connection overhead to a downstream (this reduces latency of a full handshake per-request to a downstream)
* Easily take downstream servers out of rotation.
* Various methods of load-balancing client-requests to a downstream.
* Full SSL support: including TLS false start, x509 verification, certificate caching, session caching, and all commonly used SSL configuration options.
* Transparent URI rewriting.
* Various X-Header configurations including options for added extended TLS fields.
* Upstream and downstream thresholding (to reduce memory for slow/blocking downstream connections)
* Per-downstream backlog, and backlog timeout  management.
* Flexible logging configuration.
* Optional memory optimizations on systems which support mallopt() 
* Very low memory usage with optimal configuration.
* It's really @#$@#$r* fast. 


## Configuration
RProxy global configuration options may be defined outside of other
sub-directives:

		daemonize  = true
		user       = nobody
		group      = nobody
		memtrim-sz = 0
		max-nofile = 10000

* `daemonize`   if set to true, the server will run in the background. (default: false)
* `user`        user the server will run as
* `group`       group the server will run as
* `memtrim-sz`  if your system supports mallopt, sets minimum size (in bytes) of the top-most, releasable chunk that will cause sbrk to be called with a negative argument in order to return memory to the system. 
* `max-nofile`  if your system supports set/getrlimits, this sets the maximum number of file-descriptors which can be open. It is suggested this be set to a very high number. (default: 100000).
** To adjust global limits, on OSX `sudo launchctl limit maxfiles 590000 590000`, on Linux: add `* hard nofile 590000` to your /etc/security/limits.conf

RProxy server configuration contains one or more "server" directives. Each of these
directives define how a single front-end proxy should behave. A basic server
configuration contains the following types of information:

* What address and port to bind to.
* How many listener threads to spawn.
* Optional SSL configuration directives.
* Optional request logging configuration directives.
* One or more URI rewrite configuration directives.
* One or more Downstream configuration directives.

<pre>
	server {
		addr    = "127.0.0.1"
		port    = 443
		backlog = 1024
		threads = 4

		read-timeout    = 60
		write-timeout   = 32
		pending-timeout = 10
		max-pending     = 50
		lb-method       = rtt

		logging {
			# See Logging Configuration
		}

		headers {
			# See Header Configuration
		}

		ssl {
			# See SSL Configuration
		}

		rewrite {
			# See URI Rewrite Configuration
		}

		downstream {
			# See Downstream Configuration
		}

		downstream {
			# See Downstream Configuration
		}
	}
</pre>

* `addr` is the IP address to bind
* `port` is the TCP port to bind
* `backlog` is the backlog passed to listen()
* `threads` the number of request worker threads to spawn
* `read-timeout` seconds to wait for an Upstream connection to make a request.
* `write-timeout` seconds to wait for a blocking write to an Upstream connection.
* `pending-timeout` seconds to wait for a downstream connection to be available for a connection before a 503 is returned.
* `max-pending` the number of concurrent requests in a pending state.
* `lb-method` the method which is used for load-balancing. The following methods are available 
	* `rtt` (default) based on prior requests, chooses a downstream connection from all configured downstreams with the lowest Round Trip Time.
	* `roundrobin` will send each request to a different configured downstream.
	* `most-idle` chooses the downstream with the most idle connections.
	* `none` simply chooses the first available connection it can find (no calculation of sorts).

### Downstream Configuration.

One or more downstreams can be configured. Each downstream is directly tied to
the parent server, this allows for a user to balance upstream client requests
over multiple downstream servers.

Inside each downstream directive contains the following types of information:

* The IP address of the downstream server.
* The TCP Port of the downstream server.
* The number of connections to always maintain to support HTTP pipelining.
* Retry configuration which is used to reconnect to a downstream the proxy considers to be unavailable.
* Timeouts and Thresholding.


<pre>
	downstream {
		addr           = 127.0.0.1
		port           = 80
		connections    = 10
		high-watermark = 5242880
		read-timeout   = 0
		write-timeout  = 2

		retry {
			# See Downstream Retry Configuration
		}
	}
</pre>

* `addr` is the IP address of the Downstream.
* `port` is the TCP port of the Downstream.
* `connections` the number of connections to always keep established to the downstream.
* `high-watermark` if a downstream's write-buffer goes over this number, the upstream processing is paused until all data has been writen to the downstream. This helps with slow xfer to a downstream so that memory usage does not blow up. As soon as all data has been written, the upstream is resumed.
* `read-timeout` seconds to wait for reading data from a downstream when an upstream request is made.
* `write-timeout` seconds to wait for data to be written to a downstream when an upstream request is made.

In the above configuration, a single server instance will connect to "127.0.0.1" on port 80, with a max of 10 persistent connections.

#### Downstream Retry Configuration

When a downstream has been marked as down (thus having been closed), this configuration is used to determine when the proxy should attempt to re-establish the connection. If the pending data-to-write-buffer goes over 5242880 bytes (5MB), rproxy will stop reading data from the upstream until all data has been written to the downstream. Finally, if it takes more than 2 seconds to write **any** data to the downstream, the connection to both the downstream will be terminated, while the upstream is returned a 503 response.

<pre>
	retry {
		seconds  = 0
		useconds = 5000
	}
</pre>

In the above configuration, when the downstream connection is down the proxy will attempt to reconnect every 0.5000 seconds.

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


### Downstream Rewrite Configuration

One or more URI rewrite configurations must be defined in order to establish a mapping between upstream requests to a downstream request.

<pre>
	rewrite {
		src = "^(/dir/).*"
		dst = "/derp/"
	}
</pre>

The `src` directive is a regular expression (with at least one match) that would be rewritten to the downstream `dst`. Here is an example of what happens using the above configuration.

When an upstream client makes this request to the proxy:

<pre>
GET /dir/something/file.html HTTP/1.1
Host: mandiant.com

</pre>

The proxy will rewrite the request to the downstream connection as:

<pre>
GET /derp/something/file.html HTTP/1.1
Host: mandiant.com

</pre>


### Server Logging Configuration

Each server can be configured with different log types and formats. A format is a special string which represents a piece of data in a request. These special strings are encapsulated inside {}. All other non-defined characters will be treated as text to be included within the log.

There are currently two log types, each with their own specific options.

* `file` informs rproxy to log to the file `filename`
* `syslog` informs rproxy to log using syslog to using the `facility`

<pre>
	logging {
		enabled  = true
		format   = "{SRC} {PROXY} [{TS}] \"{METH} {URI} {PROTO}\" - {STATUS} - \"{REF}\" - \"{UA}\" - \"{HOST}\" {US_HDR}:'Accept-Encoding' - {DS_HDR}:'Content-Type'"
		type     = file
		filename = /var/log/access.log
		# facility = local0
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


