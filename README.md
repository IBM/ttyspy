# ttyspy

Originally written by Dustin Lundquist to provide secure terminal sessions for
SSH Bastion servers at Blue Box.  It is primarily used inside
[Cuttle](https://github.com/IBM/cuttle) where it helps provide a secure SRE
platform for operating distributed systems in the DataCenter or in the Cloud.

Terminal sessions may include cryptographic secrets, personally identifiable
information, or other information which should not be disclosed.

The client ttyspy acts like the script(1) command, except rather than writing a
local file it sends the terminal session to (presumably secure) terminal
session archive server. To protect the contents of the terminal session and
ensure the session is sent to the correct server, TLS with mutual certificate
validation is used to authenticate both the client and server.

See the [extended documentation](doc/ttyspy.md) for detailed information about
the architecture and configuration.

## Client

The client functions as script(1) with the typescript output file piped to
curl(1). Originally implemented by wrapping these two utilities using a named
pipe between the two, but the non-deterministic order in which these utilities
would open the pipe prevented this method.

The client and server use TLS mutual certificate authentication. In order to
prevent an unprivileged user from obtaining the client's certificate private
key the client is separated into two processes: ttyspy and ttyspyd. Otherwise a
malicious user could forge transcripts implicating other users or DoS the
session_receiver server.

TTYspyd runs as a user with access to the client private key and accepts
connections on a UNIX socket. It then looks up the connecting user, establishes
a connection to the session_receiver server and includes HTTP headers
specifying the user and hostname.


### Dependencies

* Autotools (autoconf, automake)
* libcurl

### Building

```
cd client
autoreconf --install
./configure
make
```

### Installation

A certificate authority for ttyspy clients should be established. These will be
used to authenticate clients connecting to the session_receiver server. Both
ttyspy and ttyspyd user a common configuration file: /etc/ttyspy/ttyspy.conf.

    # User which ttyspyd runs as
    username       daemon

    # Unix socket where ttyspy client connect to ttyspyd and ttyspyd listens
    # for clients
    socket         /tmp/ttyspy.sock

    # URL of transcript archive server running session_receiver
    endpoint       https://server.test/transcript

    # TLS certificate authority to validate session_receiver's server
    # certificate against
    ca_path        /etc/ttyspy/ca.pem

    # TLS certificate used by ttyspyd to authenticate
    cert_path      /etc/ttyspy/client.pem

    # TLS private key used by ttyspyd to authenticate, this may point to a
    # single PEM file containing the certificate and private key. This file's
    # permission should be restricted so users can not read the private key.
    key_path       /etc/ttyspy/client.pem

This configuration contains directives that only apply to ttyspyd, and are
simply ignored by ttyspy. Arrangements should be made for ttyspyd be started
automatically at boot.

For interactive session logging, arrangements should be made to invoke ttyspy
at login such as sshd's ForceCommand directive e.g. `ForceCommand
/usr/bin/ttyspy`.


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
