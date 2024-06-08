//
// Created by Tuposoft Collective on 23.01.2023.
//

#pragma once

#ifdef WIN32

#include <windns.h>
#include <windows.h>
#include <winsock2.h>

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

namespace tuposoft::vrf {
    enum class vrf_result { success, invalid_email, failure, catch_all_detected, invalid_domain, mx_record_not_found };

    struct vrf_data {
        std::string email;
        std::string username;
        std::string domain;
        std::string mx_record;
        vrf_result result;
        bool catch_all;
    };

    std::ostream &operator<<(std::ostream &os, const vrf_data &data);

    auto verify(const std::string &email) -> vrf_data;

    auto extract_email_parts(const std::string &email) -> std::pair<std::string, std::string>;

    auto get_mx_records(const std::string &domain) -> std::vector<std::string>;
} // namespace tuposoft::vrf
