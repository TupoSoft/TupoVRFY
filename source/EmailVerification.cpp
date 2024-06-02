//
// Created by Tuposoft Collective on 23.01.2023.
//

#include "EmailVerification.hpp"

#include <vector>
#include <memory>
#include <format>

using namespace TupoSoft::VRF;

static bool verbose;

// static VRF_err_t
// send_command(int sock, char *format, ...) {
//     va_list args;
//     va_start(args, format);
//     char *command;
//     if (vasprintf(&command, format, args) < 0) {
//         return VRF_ERR;
//     }
//
//     if (verbose) printf("REQUEST: %s", command);
//
//     if (send(sock, command, strlen(command), 0) < 0) {
//         return VRF_ERR;
//     }
//     va_end(args);
//     free(command);
//
//     return VRF_OK;
// }

// static VRF_err_t
// read_response(int sock, char *buffer) {
//     auto b = (char (*)[SMTP_DATA_LINES_MAX_LENGTH]) buffer;
//     ssize_t nbytes;
//     if ((nbytes = read(sock, *b, sizeof *b)) < 0) {
//         printf("Failed to read from socket.\n");
//         return VRF_ERR;
//     }
//
//     if (verbose) printf("RESPONSE: %s", (char *) b);
//
//     //    memset(*b, 0, nbytes);
//     return VRF_OK;
// }

auto TupoSoft::VRF::extractLocalPartAndDomain(const std::string &email) -> std::pair<std::string, std::string> {
    if (const auto atPosition = email.find('@'); atPosition != std::string::npos) {
        auto username = email.substr(0, atPosition);
        auto domain = email.substr(atPosition + 1);
        return {username, domain};
    }

    throw std::invalid_argument("Invalid email format");
}

// static VRF_err_t
// check_mx(char *email, struct addrinfo *adrrinfo, EmailVerificationData *result) {
//     int sock, client_fd;
//     if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
//         printf("Failed to create a socket.\n");
//         return VRF_ERR;
//     }
//
//     char buffer[SMTP_DATA_LINES_MAX_LENGTH];
//     if ((client_fd = connect(sock, (struct sockaddr *) adrrinfo->ai_addr, sizeof(struct sockaddr))) < 0) {
//         printf("Connection failed.\n");
//         return VRF_ERR;
//     }
//
//     if (verbose) printf("SUCCESSFULLY CONNECTED TO %s\n", (*result)->mx_record);
//
//     int err;
//     CHECK_OK(read_response(sock, buffer), err)
//     CHECK_OK(send_command(sock, "EHLO %s\n", CLIENT_MX), err)
//     CHECK_OK(read_response(sock, buffer), err)
//     CHECK_OK(send_command(sock, "MAIL FROM: <%s>\n", CLIENT_EMAIL), err)
//     CHECK_OK(read_response(sock, buffer), err)
//     CHECK_OK(send_command(sock, "RCPT TO: <%s>\n", email), err)
//     CHECK_OK(read_response(sock, buffer), err)
//     char status[4];
//     memcpy(status, buffer, 3);
//     status[3] = '\0';
//     long code = strtol(status, NULL, 0);
//     if (!code) return VRF_ERR;
//     (*result)->result = code == 250;
//
//     CHECK_OK(send_command(sock, "QUIT\n"), err);
//
//     return !close(client_fd) ? VRF_OK : VRF_ERR;
// }

auto printVerificationData(std::ostream &os, EmailVerificationData emailVerificationData) -> std::ostream & {
    os << std::format("\nVerification summary:\n"
                      "email: {}\n"
                      "local part: {}\n"
                      "domain: {}\n"
                      "mx record: {}\n"
                      "result: {}\n"
                      "catch_all: {}\n\n",
                      emailVerificationData.email,
                      emailVerificationData.username,
                      emailVerificationData.domain,
                      emailVerificationData.mxRecord,
                      emailVerificationData.result == EmailVerificationResult::Success ? "true" : "false",
                      emailVerificationData.catchAll ? "true" : "false");

    return os;
}

auto TupoSoft::VRF::getMXRecords(const std::string &domain) -> std::vector<std::string> {
    addrinfo addrinfoHints{};
    addrinfoHints.ai_socktype = SOCK_STREAM;

    auto mxRecordInfoList = new addrinfo;
    if (const auto error = getaddrinfo(domain.c_str(), SMTP_SERVICE, &addrinfoHints, &mxRecordInfoList)) {
        throw std::runtime_error(std::format("Failed to get address info for domain {}, error: {}", domain,
                                             gai_strerror(error)));
    }

    const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> mxRecordInfos{mxRecordInfoList, freeaddrinfo};

    std::vector<std::string> recordAddresses{};
    for (const auto *mxRecordInfo = mxRecordInfos.get(); mxRecordInfo != nullptr;
         mxRecordInfo = mxRecordInfo->ai_next) {
        std::string address{};
        getnameinfo(mxRecordInfo->ai_addr, static_cast<socklen_t>(mxRecordInfo->ai_addrlen), address.data(),
                    address.size(),
                    nullptr, 0, NI_NUMERICHOST);

        recordAddresses.emplace_back(address);
    }

    return recordAddresses;
}

auto TupoSoft::VRF::verify(const std::string &email) -> EmailVerificationData {
    return {};
}
