//
// Created by Tuposoft Collective on 23.01.2023.
//

#include "EmailVerification.hpp"

#include <ares.h>
#include <fmt/format.h>

#include <array>
#include <iostream>
#include <memory>
#include <vector>

using namespace tuposoft::vrf;

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

auto tuposoft::vrf::extract_email_parts(const std::string &email) -> std::pair<std::string, std::string> {
    if (const auto at_position = email.find('@'); at_position != std::string::npos) {
        auto username = email.substr(0, at_position);
        auto domain = email.substr(at_position + 1);
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

auto tuposoft::vrf::get_mx_records(const std::string &domain) -> std::vector<std::string> {
    std::vector<std::string> mx_records{};
    ares_channel channel{};

    // Initialize the library
    if (ares_init_options(&channel, nullptr, 0) != ARES_SUCCESS) {
        return mx_records;
    }

    // Start the query for MX records
    ares_query_dnsrec(
            channel, domain.c_str(), ARES_CLASS_IN, ARES_REC_TYPE_MX,
            +[](void *arg, const ares_status_t status, size_t, const ares_dns_record_t *dnsrec) {
                const auto mxrs = static_cast<std::vector<std::string> *>(arg);
                if (status != ARES_SUCCESS) {
                    return; // Handle error: status will tell you what went wrong
                }

                for (auto i = 0; i < ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER); ++i) {
                    const auto rr =
                            ares_dns_record_rr_get(const_cast<ares_dns_record_t *>(dnsrec), ARES_SECTION_ANSWER, i);
                    if (!rr) {
                        return;
                    }

                    if (ares_dns_rr_get_class(rr) == ARES_CLASS_IN && ares_dns_rr_get_type(rr) == ARES_REC_TYPE_MX) {
                        mxrs->emplace_back(ares_dns_rr_get_str(rr, ARES_RR_MX_EXCHANGE));
                    }
                }
            },
            &mx_records, nullptr);

    // The main event loop - we use select here, but your application might use another approach
    for (;;) {
        fd_set read_fds, write_fds;
        timeval tv{};

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        const auto nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0) {
            break; // No more active queries
        }

        timeval *tvp = ares_timeout(channel, nullptr, &tv);
        select(nfds, &read_fds, &write_fds, nullptr, tvp);
        ares_process(channel, &read_fds, &write_fds);
    }

    ares_destroy(channel);
    return mx_records;
}

auto tuposoft::vrf::operator<<(std::ostream &os, const vrf_data &data) -> decltype(os) {
    os << fmt::format("\nVerification summary:\n"
                      "email: {}\n"
                      "username: {}\n"
                      "domain: {}\n"
                      "mx_record: {}\n"
                      "result: {}\n"
                      "catch_all: {}\n\n",
                      data.email, data.username, data.domain, data.mx_record,
                      data.result == vrf_result::success ? "true" : "false", data.catch_all ? "true" : "false");

    return os;
}

auto tuposoft::vrf::verify(const std::string &email) -> vrf_data { return {}; }
