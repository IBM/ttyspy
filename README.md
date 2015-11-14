# ttyspy

Machanism for logging terminal sessions in a secure manner.

Terminal sessions may include cryptographics secrets, personally identifiable information, or other information which should not be disclosed.

The client ttyspy acts like the script(1) command, except rather than writting a local file it sends the terminal session to (presumably secure) terminal session archive server. To protect the contents of the terminal session and ensure the session is sent to the correct server, TLS with multual certificate authentication is used.

The client reads /etc/ttyspy.conf for server endpoint, and certificates to use.

## Client

### Building

```
cd client
autoreconfig --install
./configure
make
```

## Server

### Building

```
cd src/session_receiver
go build
```
