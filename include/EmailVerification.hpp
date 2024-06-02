//
// Created by Tuposoft Collective on 23.01.2023.
//

#pragma once

#ifdef WIN32

#include <winsock2.h>
#include <windns.h>

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

#include <resolv.h>
#endif

#define SMTP_SERVICE "smtp"
#define SMTP_DATA_LINES_MAX_LENGTH 998

#include <string>
#include <vector>

namespace TupoSoft::VRF {
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

    auto verify(const std::string &email) -> EmailVerificationData;

    auto extractLocalPartAndDomain(const std::string &email) -> std::pair<std::string, std::string>;

    auto getMXRecords(const std::string &domain) -> std::vector<std::string>;
}
