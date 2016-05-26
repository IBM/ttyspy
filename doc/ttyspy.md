## Architecture
The sshd on the logged host should be configured to launch ttyspy with `ForceCommand`, and have `PermitRootLogin no`.

```text
               ┌───────────────────────── yama ──────────────────────────┐
               │ ┌────────┐                           other ttyspys      │
 ssh client ───┼─▶  sshd  │                           │     │     │      │
               │ └┬───────┘                           │     │     │      │
               │  │ForceCommand ttyspy    domain      │     │     │      │
               │  │      ┌──────────┐     socket  ┌───▼─────▼─────▼───┐  │
               │  └──────▶  ttyspy  ├─────────────▶      ttyspyd      │  │
               │         └──────────┘             └─────┬─────────────┘  │
               └────────────────────────────────────────┼────────────────┘
                                                        │                 
                                                        │ https           
                                                        │                 
               ┌─────────────────────  log server  ─────┼────────────────┐
               │                                        │                │
               │                                        │                │
               │                            ┌───────────▼─────────────┐  │
               │                            │ ttyspy session receiver │  │
               │                            └─────────────────────────┘  │
               │                                                         │
               │                                                         │
               └─────────────────────────────────────────────────────────┘
```

When invoked by the `sshd`, ttyspy will:

1. Check if the logged in user is root, and if so, [skip logging entirely](https://github.blueboxgrid.com/blue-box-cloud/ttyspy/blob/4890463ed0b7f80cf84f177a1d7b040fe3418a95/client/src/ttyspy.c#L72-L74).
2. If the stdin is not a tty, it will [log the `SSH_ORIGINAL_COMMAND` before executing it](https://github.blueboxgrid.com/blue-box-cloud/ttyspy/blob/4890463ed0b7f80cf84f177a1d7b040fe3418a95/client/src/ttyspy.c#L84-L94).
3. Otherwise, it will act similar to [`script(1)`](http://man7.org/linux/man-pages/man1/script.1.html), and log the terminal session.

## Logging configuration
`ttyspyd` and the `session_receiver` go server require you to correctly set up TLS for it to work—it is not possible to
configure it to skip certificate validation on either side. A test CA and client and server certificates (latter with the CN `server.test`)
are provided in the repo. On the client side, be sure to add a `server.test` entry in your `/etc/hosts` when testing.

You need:

1. A client certificate (with X509v3 [clientAuth extended key usage](https://www.openssl.org/docs/manmaster/apps/x509v3_config.html#Extended-Key-Usage)) signed by a CA
2. A server certificate signed by a CA

If you're unfamiliar with TLS certificate authentication, the client and server certs do _not_ have to be signed by the same CA.
`ttyspyd` will use the standard curl bundle for certificate auth if you don't give it a CA bundle.

The logging server only has a route defined for POSTing to `/transcript`, so `endpoint` in `ttyspy.conf` will always be
`https://{server}:{port}/transcript`.
