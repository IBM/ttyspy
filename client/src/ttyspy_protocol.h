#ifndef TTYSPY_PROTOCOL_H
#define TTYSPY_PROTOCOL_H

struct TTYSpyRequest {
    char login_tty[256];
    char ssh_client[256]; /* Size bounded in OpenSSH session.c */
};

#endif
