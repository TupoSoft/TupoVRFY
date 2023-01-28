//
// Created by Tuposoft Collective on 23.01.2023.
//

#pragma once

#define SMTP_DATA_LINES_MAX_LENGTH 998

#include <stdbool.h>
#include "config.h"

typedef struct
Vrf {
    char *email;
    char *local_part;
    char *domain;
    char *mx_record;
    char *mx_domain;
    bool result;
    bool catch_all;
} Vrf;

void
print_vrf(FILE *fd, Vrf *result);

void
free_vrf(Vrf *result);

int
verify(Vrf **result);
