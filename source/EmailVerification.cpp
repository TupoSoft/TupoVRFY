//
// Created by Tuposoft Collective on 23.01.2023.
//

#include "EmailVerification.hpp"

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
    std::vector<std::string> records;

#ifdef WIN32
    PDNS_RECORD p_dns_record{};

    if (const auto status =
                DnsQuery_A(domain.c_str(), DNS_TYPE_MX, DNS_QUERY_STANDARD, nullptr, &p_dns_record, nullptr)) {
        throw std::runtime_error(fmt::format("DNS query failed with error code: {}", status));
    }

    auto dns_record_deleter = [](const PDNS_RECORD &p) { DnsRecordListFree(p, DnsFreeRecordList); };
    std::unique_ptr<DNS_RECORD, decltype(dns_record_deleter)> dns_records(p_dns_record, dns_record_deleter);

    while (dns_records) {
        if (dns_records->wType == DNS_TYPE_MX) {
            records.emplace_back(dns_records->Data.MX.pNameExchange);
        }

        dns_records.reset(dns_records->pNext);
    }
#else
    std::array<unsigned char, NS_PACKETSZ> response{};
    ns_msg handle;
    ns_rr rr;
    int len;

    const std::unique_ptr<struct __res_state, decltype(&res_nclose)> res_state_ptr(new struct __res_state, res_nclose);
    const auto res_state = res_state_ptr.get();
    if (res_ninit(res_state)) {
        throw std::runtime_error{"res_ninit failed!"};
    }

    if (len = res_nsearch(res_state, domain.c_str(), ns_c_in, ns_t_mx, response.data(), response.size()); len < 0) {
        throw std::runtime_error{"res_search failed!"};
    }

    if (ns_initparse(response.data(), len, &handle) < 0) {
        throw std::runtime_error{"ns_initparse failed!"};
    }

    for (auto ns_index = 0; ns_index < ns_msg_count(handle, ns_s_an); ns_index++) {
        if (!ns_parserr(&handle, ns_s_an, ns_index, &rr) && ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_mx) {
            std::array<char, NS_MAXDNAME> mxname{};
            dn_expand(ns_msg_base(handle), ns_msg_base(handle) + ns_msg_size(handle), ns_rr_rdata(rr) + NS_INT16SZ,
                      mxname.data(), mxname.size());
            records.emplace_back(mxname.data());
        }
    }
#endif

    return records;
}

std::ostream &tuposoft::vrf::operator<<(std::ostream &os, const vrf_data &data) {
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
