//
// Created by Tuposoft Collective on 23.01.2023.
//

#pragma once

#define SMTP_DATA_LINES_MAX_LENGTH 998

#include <stdbool.h>
#include "config.h"

typedef struct VRF *VRF;

typedef enum
VRF_err {
    VRF_ERR = -1,
    VRF_OK,
} VRF_err;

VRF_err
print_vrf(FILE *, VRF);

void
free_vrf(VRF);

VRF_err
verify(VRF *);
