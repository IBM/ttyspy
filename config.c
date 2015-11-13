#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "cfg_parser.h"


static int accept_endpoint(struct Config *, char *);
static int accept_ca_path(struct Config *, char *);
static int accept_cert_path(struct Config *, char *);
static int accept_key_path(struct Config *, char *);


static struct Keyword global_grammar[] = {
    { "endpoint",
        NULL,
        (int(*)(void *, char *))accept_endpoint,
        NULL,
        NULL},
    { "ca_path",
        NULL,
        (int(*)(void *, char *))accept_ca_path,
        NULL,
        NULL},
    { "cert_path",
        NULL,
        (int(*)(void *, char *))accept_cert_path,
        NULL,
        NULL},
    { "key_path",
        NULL,
        (int(*)(void *, char *))accept_key_path,
        NULL,
        NULL},
    { NULL, NULL, NULL, NULL, NULL }
};


struct Config *
load_config(const char *filename) {
    struct Config *config = malloc(sizeof(struct Config));
    if (config != NULL) {
        /* Initialize empty config */
        config->endpoint = NULL;
        config->ca_path = NULL;
        config->cert_path = NULL;
        config->key_path = NULL;

        FILE *file = fopen(filename, "r");
        if (file == NULL) {
            fprintf(stderr, "%s: unable to open configuration file: %s", __func__, filename);
            return NULL;
        }

        if (parse_config(config, file, global_grammar) <= 0) {
            long whence = ftell(file);
            char buffer[256];

            fprintf(stderr, "error parsing %s at %ld near:", filename, whence);
            fseek(file, -20, SEEK_CUR);
            for (int i = 0; i < 5; i++)
                fprintf(stderr, "%ld\t%s", ftell(file), fgets(buffer, sizeof(buffer), file));

            config = NULL;
        }

        fclose(file);

        if (config->cert_path != NULL && config->key_path == NULL)
            config->key_path = strdup(config->cert_path);
    }

    return config;
}

static int
accept_endpoint(struct Config *config, char *endpoint) {
    config->endpoint = strdup(endpoint);
    if (config->endpoint == NULL) {
        perror("strdup");
        return -1;
    }

    return 1;
}

static int
accept_ca_path(struct Config *config, char *ca_path) {
    config->ca_path = strdup(ca_path);
    if (config->ca_path == NULL) {
        perror("strdup");
        return -1;
    }

    return 1;
}

static int
accept_cert_path(struct Config *config, char *cert_path) {
    config->cert_path = strdup(cert_path);
    if (config->cert_path == NULL) {
        perror("strdup");
        return -1;
    }

    return 1;
}

static int
accept_key_path(struct Config *config, char *key_path) {
    config->key_path = strdup(key_path);
    if (config->key_path == NULL) {
        perror("strdup");
        return -1;
    }

    return 1;
}
