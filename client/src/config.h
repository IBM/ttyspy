#ifndef CONFIG_H
#define CONFIG_H


struct Config {
    char *endpoint;
    char *cert_path;
    char *key_path;
    char *ca_path;
    char *socket;
    char *username;
};


struct Config *load_config(const char *);

#endif
