//
// Created by Tuposoft Collective on 23.01.2023.
//

#pragma once

#ifdef WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#define ISVALIDSOCKET(s) (s) != INVALID_SOCKET
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() WSAGetLastError()

#else

#define SOCKET int
#define ISVALIDSOCKET(s) (s) >= 0
#define CLOSESOCKET(s) close(s)
#define GETSOCKETERRNO() errno

#include <arpa/nameser.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#endif

#include <iostream>
#include <cstdio>
#include <getopt.h>

#define SMTP_SERVICE "smtp"
#define SMTP_DATA_LINES_MAX_LENGTH 998

#include <string>
#include <vector>

#include "config.h"

namespace TupoSoft::VRF {
    typedef enum
            VRF_err_e {
        VRF_ERR = -1,
        VRF_OK,
    } VRF_err_t;

    enum class EmailVerificationResult {
        Success,
        InvalidEmail,
        Failure,
        CatchAllDetected,
        InvalidDomain,
        MXRecordNotFound
    };

    struct EmailVerificationData {
        std::string email;
        std::string username;
        std::string domain;
        std::string mxRecord;
        EmailVerificationResult result;
        bool catchAll;
    };

    auto extractLocalPartAndDomain(const std::string &email) -> std::tuple<std::string, std::string>;

    auto getMXRecords(const std::string &domain) -> std::vector<std::string>;
}
