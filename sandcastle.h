#ifndef SANDCASTLE_H
#define SANDCASTLE_H

#include "config.h"
#include "http_server.h"
#include "sandbox.h"
#include "utils.h"

/**
 * Main sandcastle application entry point
 * @param argc Command line argument count
 * @param argv Command line argument values
 * @return 0 on success, non-zero on failure
 */
int sandcastle_main(int argc, char *argv[]);

#endif /* SANDCASTLE_H */ 