# ttyspy

Mechanism for logging terminal sessions in a secure manner.

Terminal sessions may include cryptographic secrets, personally identifiable
information, or other information which should not be disclosed.

The client ttyspy acts like the script(1) command, except rather than writing a
local file it sends the terminal session to (presumably secure) terminal
session archive server. To protect the contents of the terminal session and
ensure the session is sent to the correct server, TLS with mutual certificate
validation is used to authenticate both the client and server.

## Client

The client functions as script(1) with the typescript output file piped to
curl(1). Originally it was going to be implemented by wrapping these two
utilities using a named pipe between the two, but the non-deterministic order
in which these utilities would open the pipe prevented this method.

### Dependencies

* Autotools (autoconf, automake)
* libcurl

### Building

```
cd client
autoreconfig --install
./configure
make
```

## Server

The server is a simple Go webserver which authenticates client connections by
the client's certificate and saves HTTP POSTs to /transcript path. The server
expects a content-type of application/typescript, and X-Username, X-Hostname,
X-Gecos headers to be present. Additionally if the X-Ssh-Client header is
present it is preserved in the transcript file. Each transcript is saved into a
directory structure by username, hostname, year, month and day. This allows
archiving of old transcripts.

### Building

```
cd src/session_receiver
go build
```
