#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <curl/curl.h>
#include "config.h"
#include "ttyspy_protocol.h"


static void usage();
static void perror_exit(const char *);
static int listening_unix_socket(const char *);
static void sig_handler(int);
static int uploader(struct Config *, int);
static struct curl_slist *build_http_headers(const struct TTYSpyRequest *, const struct passwd *);


int
main(int argc, char *argv[]) {
    int ch, foreground_flag = 0;
    const char *config_file = NULL;

    while ((ch = getopt(argc, argv, "c:f")) != -1) {
        switch (ch) {
            case 'c':
                config_file = optarg;
                break;
            case 'f':
                foreground_flag = 1;
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

    struct passwd *user = getpwnam(config->username);
    if (user == NULL) {
        fprintf(stderr, "Unable to find user %s\n", config->username);
        return 0;
    }

    /* Create listening socket */
    int sock_fd = listening_unix_socket(config->socket);
    if (sock_fd < 0)
        perror_exit("listening_unix_socket()");

    if (!foreground_flag) {
        /* drop privileges if launched as root */
        if (geteuid() == 0) {
            /* including any supplementary groups */
            if (setgroups(1, &user->pw_gid) < 0)
                perror_exit("setgroups()");

            if (setgid(user->pw_gid) < 0)
                perror_exit("setgid()");

            if (setuid(user->pw_uid) < 0)
                perror_exit("setuid()");
        }

        if (daemon(0,0) < 0) {
            perror("daemon");
            return 1;
        }
    }

    /* handle SIGCHLD */
    struct sigaction sa = {
        .sa_handler = sig_handler,
        .sa_flags = SA_RESTART,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);

    /* Simple forking server */
    for(;;) {
        int client_fd = accept(sock_fd, NULL, 0);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        } else if (pid > 0) {
            /* parent */
            close(client_fd);
            continue;
        }

        /* client */
        close(sock_fd);

        uploader(config, client_fd);

        exit(0);
    }
    /* not reached */
}

static void
usage() {
    fprintf(stderr, PACKAGE ": ttyspy server\nusage: ttyspyd [-c <config_file>] [-f]\n");
    exit(1);
}

static void
perror_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void
sig_handler(int signo) {
    int status;
    pid_t pid;

    switch (signo) {
    case SIGCHLD:
        do {
            pid = waitpid(-1, &status, WNOHANG);
            if (pid > 0)
                fprintf(stderr, "child [%d] terminated with %d\n", pid, status);
            if (pid < 0 && errno != ECHILD)
                perror("waitpid");
        } while (pid > 0);
        break;
    case SIGPIPE:
        /* noop */
        break;
    default:
        fprintf(stderr, "received signal %d\n", signo);
        break;
    }
}

static int
listening_unix_socket(const char *sock_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct stat sb;
    int result = lstat(sock_path, &sb);
    if (result < 0 && errno != ENOENT) {
        perror("lstat");
        return -1;
    }
    if (result == 0) {
        if (S_ISSOCK(sb.st_mode)) {
            /* Existing socket: delete it */
            unlink(sock_path);
        } else {
            fprintf(stderr, "Socket already exists: %s", sock_path);
            return -1;
        }
    }

    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    int path_len = strlcpy(un.sun_path, sock_path, sizeof(un.sun_path));
    if (path_len >= sizeof(un.sun_path)) {
        fprintf(stderr, "Socket path too long!");
        return -1;
    }

    /* Ensure permissions allow all users to connect to socket */
    mode_t old_umask = umask(0);

    int size = offsetof(struct sockaddr_un, sun_path) + path_len;
    result = bind(fd, (struct sockaddr *)&un, size);
    if (result < 0) {
        perror("bind");
        return -1;
    }

    umask(old_umask);

    result = listen(fd, SOMAXCONN);
    if (result < 0) {
        perror("listen");
        return -1;
    }

    return fd;
}

static int
uploader(struct Config *config, int sock_fd) {
    struct TTYSpyRequest *req = malloc(sizeof(struct TTYSpyRequest));
    if (req == NULL) {
        perror("malloc");
        return 0;
    }

    uid_t uid;
    gid_t gid;
    if (getpeereid(sock_fd, &uid, &gid)) {
        fprintf(stderr, "Unable to obtain peer credentials");
        return 0;
    }

    struct passwd *user = getpwuid(uid);
    if (user == NULL) {
        fprintf(stderr, "Unable to find user for uid=%d, gid=%d\n", uid, gid);
        return 0;
    }

    /* Read complete header */
    ssize_t bytes_read = 0;
    char *pos = (char *)req;
    while (bytes_read < sizeof(struct TTYSpyRequest)) {
        ssize_t len = read(sock_fd, pos, sizeof(struct TTYSpyRequest) - bytes_read);
        if (len < 0) {
            perror("read");
            return 0;
        }
        pos += len;
        bytes_read += len;
    }

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
    FILE *transcript = fdopen(sock_fd, "r");
    if (transcript == NULL) {
        perror("fdopen");
        exit(1);
    }
    curl_easy_setopt(curl, CURLOPT_READDATA, transcript);

    struct curl_slist *http_headers = NULL;

    /* build headers */
    http_headers = build_http_headers(req, user);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        fprintf(stderr, PACKAGE ": curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));

    curl_easy_cleanup(curl);

    exit(0);
}

static struct curl_slist *
build_http_headers(const struct TTYSpyRequest *req, const struct passwd *user) {
    struct curl_slist *http_headers = NULL;
    int result;

    http_headers = curl_slist_append(http_headers, "Transfer-Encoding: chunked");
    http_headers = curl_slist_append(http_headers, "Content-Type: application/typescript");

    /* TODO store this at startup and reuse */
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

    if (strlen(req->ssh_client) > 0) {
        char *x_ssh_client = NULL;
        result = asprintf(&x_ssh_client, "X-Ssh-Client: %s", req->ssh_client);
        if (result < 0 || x_ssh_client == NULL) {
            perror(PACKAGE ": asprintf");
            exit(1);
        }
        http_headers = curl_slist_append(http_headers, x_ssh_client);
    }

    return http_headers;
}
