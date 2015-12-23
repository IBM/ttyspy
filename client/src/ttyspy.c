#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#include <pwd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#include "config.h"
#include "ttyspy_protocol.h"


static void usage() __attribute__ ((noreturn));
static void sig_handler(int);
static struct TTYSpyRequest *build_request();
static int open_ttyspy_session(const char *);
static ssize_t write_all(int, const void *, size_t);
static void exec_shell_or_command(const char *, int , char *[]) __attribute__ ((noreturn));


/* global so we can pass along window size change from signal handler: */
static int master;


int
main(int argc, char *argv[]) {
    int ch;
    const char *config_file = NULL;

    while ((ch = getopt(argc, argv, "c:")) != -1) {
        switch (ch) {
            case 'c':
                config_file = optarg;
                break;
            case '?':
            default:
                usage();
        }
    }
    argc -= optind;
    argv += optind;

    /* Read configuration */
    struct Config *config = load_config(config_file);
    if (config == NULL)
        return 1;

    /* Gather user info */
    struct passwd *user = getpwuid(getuid());
    if (user == NULL) {
        perror(PACKAGE ": getpwuid");
        return 1;
    }

    /* Skip ttyspy for root */
    if (user->pw_uid == 0)
        exec_shell_or_command(user->pw_shell, argc, argv);

    char *ident = NULL;
    int result = asprintf(&ident, "%s (%s)", PACKAGE, user->pw_name);
    if (result < 0) {
        perror("asprintf");
        return 1;
    }
    openlog(ident, LOG_PID, LOG_DAEMON);

    if (!isatty(STDIN_FILENO)) {
        syslog(LOG_NOTICE, "STDIN is not a tty");

        int ttyspyd_sock = open_ttyspy_session(config->socket);
        FILE *session = fdopen(ttyspyd_sock, "w");
        fprintf(session, "Non tty session initiated.\n");
        fprintf(session, "SSH_ORIGINAL_COMMAND=%s\n", getenv("SSH_ORIGINAL_COMMAND"));
        fclose(session);

        exec_shell_or_command(user->pw_shell, argc, argv);
    }

    /* Get terminal settings */
    struct termios term;
    result = tcgetattr(STDIN_FILENO, &term);
    if (result < 0) {
        syslog(LOG_INFO, "tcgetattr: %s", strerror(errno));
    }

    struct winsize win;
    result = ioctl(STDIN_FILENO, TIOCGWINSZ, &win);
    if (result < 0) {
        syslog(LOG_INFO, "ioctl TIOCGWINSZ: %s", strerror(errno));
    }

    /* Allocate a PTY */
    int slave = -1;
    int ret = openpty(&master, &slave, NULL, &term, &win);
    if (ret < 0) {
        syslog(LOG_ERR, "openpty: %s", strerror(errno));

        /* exec shell */
        syslog(LOG_ERR, "Unable to log current session, falling back to unlogged sesssion");
        exec_shell_or_command(user->pw_shell, argc, argv);
    }

    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "fork: %s", strerror(errno));
        close(slave);
        close(master);

        /* exec shell */
        syslog(LOG_ERR, "Unable to log current session, falling back to unlogged sesssion");
        exec_shell_or_command(user->pw_shell, argc, argv);
    } else if (pid == 0) {
        /* Child */

        /* Setup file descriptors */
        close(master);
        if (login_tty(slave) < 0) {
            syslog(LOG_ERR, "login_tty: %s", strerror(errno));
            exit(1);
        }

        /* exec shell */
        exec_shell_or_command(user->pw_shell, argc, argv);
    } else {
        /* Parent */
        close(slave);

        int ttyspyd_sock = open_ttyspy_session(config->socket);

        /* Set local terminal to raw mode */
        struct termios rawterm = term;
        cfmakeraw(&rawterm);
        rawterm.c_lflag &= ~ECHO;
        /* rawterm.cflags &= ~ECHO; */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &rawterm);

        /* Install signal handler */
        struct sigaction sa = {
            .sa_handler = sig_handler,
            .sa_flags = SA_RESTART,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGWINCH, &sa, NULL);
        sigaction(SIGCHLD, &sa, NULL);
        sigaction(SIGPIPE, &sa, NULL);

        for (;;) {
            fd_set rfds;
            fd_set efds;
            char buffer[256];
            FD_ZERO(&rfds);
            FD_ZERO(&efds);
            FD_SET(STDIN_FILENO, &rfds);
            FD_SET(STDIN_FILENO, &efds);
            FD_SET(master, &rfds);
            FD_SET(master, &efds);

            result = select(master + 1, &rfds, NULL, &efds, NULL);
            if (result < 0 && errno == EINTR) /* received signal */
                continue;
            if (result < 0) {
                syslog(LOG_INFO, "select: %s", strerror(errno));
                break;
            }
            if (FD_ISSET(STDIN_FILENO, &efds)) {
                break;
            }
            if (FD_ISSET(master, &efds)) {
                break;
            }
            if (FD_ISSET(STDIN_FILENO, &rfds)) {
                ssize_t len = read(STDIN_FILENO, buffer, sizeof(buffer));
                if (len < 0) {
                    syslog(LOG_INFO, "read STDIN: %s", strerror(errno));
                    break;
                }
                result = write_all(master, buffer, len);
                /* XXX ignored */
            }
            if (FD_ISSET(master, &rfds)) {
                ssize_t len = read(master, buffer, sizeof(buffer));
                if (len < 0) {
                    syslog(LOG_INFO, "read pty: %s", strerror(errno));
                    break;
                }
                result = write_all(STDOUT_FILENO, buffer, len);
                /* XXX ignored */
                result = write_all(ttyspyd_sock, buffer, len);
                /* XXX ignored */
            }
        }

        /* Reset terminal */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
        syslog(LOG_INFO, "exiting...");
    }

    return 0;
}

static void
usage() {
    fprintf(stderr, PACKAGE ": ttyspy client\nusage: ttyspy [-c <config_file>]\n");
    exit(1);
}

static void
sig_handler(int signo) {
    struct winsize win;
    int result;
    int status;
    pid_t pid;

    switch (signo) {
    case SIGWINCH:
        result = ioctl(STDIN_FILENO, TIOCGWINSZ, &win);
        if (result < 0) {
            syslog(LOG_INFO, "ioctl TIOCGWINSZ: %s", strerror(errno));

            break;
        }
        ioctl(master, TIOCSWINSZ, &win);
        break;
    case SIGCHLD:
        do {
            pid = waitpid(-1, &status, WNOHANG);
            if (pid > 0)
                syslog(LOG_INFO, "child [%d] terminated with %d\n", pid, status);
            if (pid < 0 && errno != ECHILD)
                syslog(LOG_ERR, "waitpid: %s", strerror(errno));
        } while (pid > 0);
        break;
    case SIGPIPE:
        /* noop */
        break;
    default:
        syslog(LOG_NOTICE, "received signal %d\n", signo);
        break;
    }
}

static struct TTYSpyRequest *
build_request() {
    struct TTYSpyRequest *req = malloc(sizeof(struct TTYSpyRequest));

    if (req != NULL) {
        memset(req, 0, sizeof(struct TTYSpyRequest));

        char *login_tty = getenv("SSH_TTY");
        if (login_tty != NULL)
            strlcpy(req->login_tty, login_tty, sizeof(req->login_tty));

        char *ssh_client = getenv("SSH_CLIENT");
        if (ssh_client != NULL)
            strlcpy(req->ssh_client, ssh_client, sizeof(req->ssh_client));
    }

    return req;
}

static int
open_ttyspy_session(const char *sock_path) {
    struct TTYSpyRequest *req = build_request();
    if (req == NULL) {
        syslog(LOG_ERR, "build_request: %s", strerror(errno));
        return -1;
    }

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        syslog(LOG_ERR, "socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    int path_len = strlcpy(un.sun_path, sock_path, sizeof(un.sun_path));
    if (path_len >= sizeof(un.sun_path)) {
        syslog(LOG_INFO, "Socket path is tool long!");
        return -1;
    }

    int size = offsetof(struct sockaddr_un, sun_path) + path_len;
    if (connect(sock_fd, (struct sockaddr *)&un, size) < 0) {
        syslog(LOG_ERR, "Unable to connect to %s: %s", sock_path, strerror(errno));
        return -1;
    }

    /* transmit ttyspy request */
    if (write_all(sock_fd, req, sizeof(struct TTYSpyRequest)) < 0) {
        syslog(LOG_INFO, "write: %s", strerror(errno));
        return -1;
    }

    return sock_fd;
}

static ssize_t
write_all(int fd, const void *src, size_t nbyte) {
    size_t bytes_written = 0;
    const char *pos = (const char *)src;
    while (bytes_written < nbyte) {
        ssize_t result = write(fd, pos, nbyte - bytes_written);
        if (result < 0) {
            return result;
        }
        pos += result;
        bytes_written += result;
    }

    return 0;
}

static void
exec_shell_or_command(const char *shell, int argc, char *argv[]) {
    char **new_argv = NULL;
    const char *ssh_orig_cmd = getenv("SSH_ORIGINAL_COMMAND");

    /* For debugging
    if (1) {
        printf("args = {");
        for (int i = 0; i < argc; i++) {
            if (i > 0)
                printf(", ");
            printf("\"%s\"", argv[i]);
        }
        printf("}\n");
    }
     */

    if (argc > 0) {
        /* If additional filter specified as argument exec it passing the
         * remaining arguments */

        new_argv = argv;
    } else if (ssh_orig_cmd != NULL) {
        /* If an SSH command was specified run it */

        new_argv = malloc(4 * sizeof(char *));
        if (new_argv != NULL) {
            new_argv[0] = (char *)shell;
            new_argv[1] = "-c";
            new_argv[2] = (char *)ssh_orig_cmd;
            new_argv[3] = NULL;
        }
    } else {
        /* Otherwise spawn the user's login shell */

        new_argv = malloc(3 * sizeof(char *));
        if (new_argv != NULL) {
            new_argv[0] = (char *)shell;
            new_argv[1] = "-l";
            new_argv[2] = NULL;
        }
    }

    if (new_argv == NULL) {
        perror("malloc new argv");
        exit(1);
    }

    execv(new_argv[0], new_argv);
    fprintf(stderr, "Unable to exec %s: %s\nA fully qualified path is required.\n", new_argv[0], strerror(errno));
    exit(1);
}
