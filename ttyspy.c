#include <pty.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <err.h>
#include <pty.h>
#include <dirent.h>



const char *config_file = "/etc/ttyspy.conf";


struct Config {
    char *endpoint;
    char *cert_path;
    char *key_path;
    char *ca_path;
};


static struct Config *load_config(const char *);
static void sig_handler(int);
static void print_fds();


int master;


int
main(int argc, char **argv) {
    int result;

    print_fds();
    /* Read configuration */
    struct Config *config = load_config(config_file);
    if (config == NULL) {
        return 1;
    }
    print_fds();

    /* Gather user info */
    struct passwd *user = getpwuid(getuid());
    if (user == NULL) {
        warn("getpwuid");
        return 1;
    }

    char *cmd = user->pw_shell;
    if (cmd == NULL)
        cmd = "/bin/sh";

    fprintf(stderr, "User shell: %s\n", cmd);

    print_fds();

    /* Get terminal settings */
    struct termios term;
    result = tcgetattr(STDIN_FILENO, &term);
    if (result < 0) {
        warn("tcgetattr");
    }

    struct winsize win;
    result = ioctl(STDIN_FILENO, TIOCGWINSZ, &win);
    if (result < 0) {
        warn("ioctl TIOCGWINSZ");
    }

    /* Allocate a PTY */
    int slave = -1;
    int ret = openpty(&master, &slave, NULL, &term, &win);

    pid_t pid = fork();
    if (pid < 0) {
        warn("forkpty");

        /* exec shell */
        execl(cmd, cmd, NULL);
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
            perror("setsid()");

        /* exec shell */
        execl(cmd, cmd, NULL);
    } else {
        /* Parent */
        close(slave);

        /* Set local terminal to raw mode */
        struct termios rawterm = term;
        cfmakeraw(&rawterm);
        rawterm.c_lflag &= ~ECHO;
        /* rawterm.cflags &= ~ECHO; */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &rawterm);

        /* Install handler for SIGWINCH */
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = sig_handler;
        sa.sa_flags = SA_RESTART;
        sigaction(SIGWINCH, &sa, NULL);

        for (;;) {
            fd_set rfds;
            char buffer[256];
            FD_ZERO(&rfds);
            FD_SET(STDIN_FILENO, &rfds);
            FD_SET(master, &rfds);

            result = select(master + 1, &rfds, NULL, NULL, NULL);
            if (result < 0) {
                warn("select");
                continue;
            }
            if (FD_ISSET(STDIN_FILENO, &rfds)) {
                result = read(STDIN_FILENO, buffer, sizeof(buffer));
                if (result < 0) {
                    warn("read STDIN");
                    break;
                }
                write(master, buffer, result);
            }
            if (FD_ISSET(master, &rfds)) {
                result = read(master, buffer, sizeof(buffer));
                if (result < 0) {
                    warn("read pty");
                    break;
                }
                write(STDOUT_FILENO, buffer, result);
            }
        }

        /* Reset terminal */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
    }

    return 0;
}

static void sig_handler(int signo) {
    struct winsize win;
    int result = ioctl(STDIN_FILENO, TIOCGWINSZ, &win);
    if (result < 0) {
        warn("ioctl TIOCGWINSZ");
        return;
    }
    ioctl(master, TIOCSWINSZ, &win);
}

static struct Config *load_config(const char *path) {
    /* TODO */
    return (struct Config *)path;
}

static void print_fds() {
    fprintf(stderr, "Open files:\n");
    char cmdline[512];
    sprintf(cmdline, "/bin/ls -l /proc/%d/fd", getpid());
    FILE *cmd = popen(cmdline, "r");
    if (cmd == NULL) {
        perror("popen");
    } else {
        char buffer[4096];
        size_t len = 0;

        while ((len = fread(buffer, 1, sizeof(buffer), cmd)) > 0)
            fwrite(buffer, len, 1, stderr);

        pclose(cmd);
    }
}

