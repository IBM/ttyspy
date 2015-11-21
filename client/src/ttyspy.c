#include <dirent.h>
#include <err.h>
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#include <curl/curl.h>
#include "config.h"



static const char *config_file = "/etc/ttyspy.conf";
static int master;

static void sig_handler(int);
static int spawn_uploader(struct Config *, struct passwd *);
static struct curl_slist *build_http_headers(const struct passwd *);
static void exec_shell_or_command(const char *, int , char *[]) __attribute__ ((noreturn));


int
main(int argc, char *argv[]) {
    int result;

    /* Read configuration */
    struct Config *config = load_config(config_file);
    if (config == NULL) {
        return 1;
    }

    /* Gather user info */
    struct passwd *user = getpwuid(getuid());
    if (user == NULL) {
        warn(PACKAGE ": getpwuid");
        return 1;
    }

    /* Get terminal settings */
    struct termios term;
    result = tcgetattr(STDIN_FILENO, &term);
    if (result < 0) {
        warn(PACKAGE ": tcgetattr");
    }

    struct winsize win;
    result = ioctl(STDIN_FILENO, TIOCGWINSZ, &win);
    if (result < 0) {
        warn(PACKAGE ": ioctl TIOCGWINSZ");
    }

    /* Allocate a PTY */
    int slave = -1;
    int ret = openpty(&master, &slave, NULL, &term, &win);
    if (ret < 0) {
        perror(PACKAGE ": openpty");

        /* exec shell */

        exec_shell_or_command(user->pw_shell, argc, argv);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror(PACKAGE ": fork");
        close(slave);
        close(master);

        /* exec shell */
        exec_shell_or_command(user->pw_shell, argc, argv);
    } else if (pid == 0) {
        /* Child */

        /* Setup file descriptors */
        close(master);
        dup2(slave, STDIN_FILENO);
        dup2(slave, STDOUT_FILENO);
        dup2(slave, STDERR_FILENO);
        close(slave);

        /* Make session group leader */
        if (setsid() < 0)
            perror(PACKAGE ": setsid()");

        /* exec shell */
        exec_shell_or_command(user->pw_shell, argc, argv);
    } else {
        /* Parent */
        close(slave);

        /* Fork a child to handle streaming the session to the logging server */
        int transcript_pipe = spawn_uploader(config, user);

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
            if (result < 0) {
                warn(PACKAGE ": select");
                continue;
            }
            if (FD_ISSET(STDIN_FILENO, &efds)) {
                break;
            }
            if (FD_ISSET(master, &efds)) {
                break;
            }
            if (FD_ISSET(STDIN_FILENO, &rfds)) {
                result = read(STDIN_FILENO, buffer, sizeof(buffer));
                if (result < 0) {
                    warn(PACKAGE ": read STDIN");
                    break;
                }
                result = write(master, buffer, result);
                /* XXX ignored */
            }
            if (FD_ISSET(master, &rfds)) {
                result = read(master, buffer, sizeof(buffer));
                if (result < 0) {
                    warn(PACKAGE ": read pty");
                    break;
                }
                result = write(STDOUT_FILENO, buffer, result);
                /* XXX ignored */
                result = write(transcript_pipe, buffer, result);
                /* XXX ignored */
            }
        }

        /* Reset terminal */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
        fprintf(stderr, PACKAGE " exiting...\n");
    }

    return 0;
}

static void sig_handler(int signo) {
    struct winsize win;
    int result;
    int status;
    pid_t pid;

    switch (signo) {
    case SIGWINCH:
        fprintf(stderr, PACKAGE ": received SIGWINCH\n");
        result = ioctl(STDIN_FILENO, TIOCGWINSZ, &win);
        if (result < 0) {
            warn(PACKAGE ":ioctl TIOCGWINSZ");
            return;
        }
        ioctl(master, TIOCSWINSZ, &win);
        break;
    case SIGCHLD:
        do {
            pid = waitpid(-1, &status, WNOHANG);
            if (pid > 0)
                fprintf(stderr, PACKAGE ": child [%d] terminated with %d\n", pid, status);
            if (pid < 0)
                perror(PACKAGE ": waitpid");
        } while (pid > 0);
        break;
    case SIGPIPE:
        /* noop */
        break;
    default:
        fprintf(stderr, PACKAGE ": received signal %d\n", signo);
        break;
    }
}

/*
 * Spawn a child process to handle the actual HTTPS POST process
 * This allows us to use curl_easy_perform and still multiplex master PTY and
 * standard IO in parent
 *
 * Returns file descriptor of pipe to child
 */
static int
spawn_uploader(struct Config *config, struct passwd *user) {
    int pipefd[2];

    if (pipe(pipefd) < 0) {
        perror(PACKAGE ": pipe");
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror(PACKAGE ": fork");
        return -1;
    } else if (pid > 0) {
        /* parent */
        close(pipefd[0]);

        return pipefd[1];
    }

    /* child */
    close(master);
    close(pipefd[1]);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);


    curl_global_init(CURL_GLOBAL_ALL);
    CURL *curl = curl_easy_init();

    /* Send keep-alives */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 10L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 3L);

    /* Verify server certificate and provide client certificate */
    if (config->cert_path && config->key_path) {
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLCERT, config->cert_path);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, config->key_path);
    }
    if (config->ca_path) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, config->ca_path);
    }

    curl_easy_setopt(curl, CURLOPT_URL, config->endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    FILE *transcript = fdopen(pipefd[0], "r");
    if (transcript == NULL) {
        perror(PACKAGE ": fdopen");
        exit(1);
    }
    curl_easy_setopt(curl, CURLOPT_READDATA, transcript);

    struct curl_slist *http_headers = NULL;

    /* build headers */
    http_headers = build_http_headers(user);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        fprintf(stderr, PACKAGE ": curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));

    curl_easy_cleanup(curl);

    exit(0);
}

static struct curl_slist *
build_http_headers(const struct passwd *user) {
    struct curl_slist *http_headers = NULL;
    int result;

    http_headers = curl_slist_append(http_headers, "Transfer-Encoding: chunked");
    http_headers = curl_slist_append(http_headers, "Content-Type: application/typescript");

    char *hostname = malloc(256);
    if (hostname == NULL) {
        perror(PACKAGE ": malloc");
        exit(1);
    }
    gethostname(hostname, 256);
    char *x_hostname = NULL;
    result = asprintf(&x_hostname, "X-Hostname: %s", hostname);
    if (result < 0 || x_hostname == NULL) {
        perror(PACKAGE ": asprinf");
        exit(1);
    }
    http_headers = curl_slist_append(http_headers, x_hostname);

    char *x_username = NULL;
    result = asprintf(&x_username, "X-Username: %s", user->pw_name);
    if (result < 0 || x_username == NULL) {
        perror(PACKAGE ": asprintf");
        exit(1);
    }
    http_headers = curl_slist_append(http_headers, x_username);

    char *x_gecos = NULL;
    result = asprintf(&x_gecos, "X-Gecos: %s", user->pw_gecos);
    if (result < 0 || x_gecos == NULL) {
        perror(PACKAGE ": asprintf");
        exit(1);
    }
    http_headers = curl_slist_append(http_headers, x_gecos);

    char *ssh_client = getenv("SSH_CLIENT");
    if (ssh_client) {
        char *x_ssh_client = NULL;
        result = asprintf(&x_ssh_client, "X-Ssh-Client: %s", getenv("SSH_CLIENT"));
        if (result < 0 || x_ssh_client == NULL) {
            perror(PACKAGE ": asprintf");
            exit(1);
        }
        http_headers = curl_slist_append(http_headers, x_ssh_client);
    }

    return http_headers;
}

static void
exec_shell_or_command(const char *shell, int argc, char *argv[]) {
    /* If additional filter specified as argument exec it passing the
     * remaining arguments */
    if (argc > 1) {
        char **new_argv = malloc(argc * sizeof(char *));
        if (new_argv == NULL) {
            perror(PACKAGE ": malloc");
            exit(1);
        }

        for (int i = 0; i < argc - 1; i++)
            new_argv[i] = argv[i + 1];
        new_argv[argc - 1] = NULL;

        execvp(new_argv[0], new_argv);
        perror(PACKAGE ": exec");
        exit(1);
    }

    /* If an SSH command was specified run it */
    const char *ssh_orig_cmd = getenv("SSH_ORIGINAL_COMMAND");
    if (ssh_orig_cmd != NULL) {
        char **new_argv = malloc(4 * sizeof(char *));
        if (new_argv == NULL) {
            perror(PACKAGE ": malloc");
            exit(1);
        }
        new_argv[0] = (char *)shell;
        new_argv[1] = "-c";
        new_argv[2] =(char *) ssh_orig_cmd;
        new_argv[3] = NULL;

        execv(new_argv[0], new_argv);
        perror(PACKAGE ": exec");
        exit(1);
    }

    /* Otherwise spawn the user's login shell */
    char **new_argv = malloc(3 * sizeof(char *));
    new_argv[0] = (char *)shell;
    new_argv[1] = "-l";
    new_argv[2] = NULL;
    execv(new_argv[0], new_argv);
    perror(PACKAGE ": exec");
    exit(1);
}
