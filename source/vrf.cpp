//
// Created by Tuposoft Collective on 23.01.2023.
//

#include "vrf.hpp"
#include "asio/io_service.hpp"

#include <ares.h>
#include <asio.hpp>
#include <fmt/format.h>

#include <iostream>
#include <regex>
#include <vector>

#include "socket_wrapper.hpp"

using namespace tuposoft::vrf;


auto tuposoft::vrf::extract_email_parts(const std::string &email) -> std::pair<std::string, std::string> {
    static const auto email_regex = std::regex(R"((\w+[\w\.]*)@(\w+\.\w+))");

    if (auto matches = std::smatch(); std::regex_search(email, matches, email_regex)) {
        return {matches[1], matches[2]};
    }

    throw std::invalid_argument("Invalid email format");
}

//     CHECK_OK(read_response(sock, buffer), err)
//     CHECK_OK(send_command(sock, "EHLO %s\n", CLIENT_MX), err)
//     CHECK_OK(read_response(sock, buffer), err)
//     CHECK_OK(send_command(sock, "MAIL FROM: <%s>\n", CLIENT_EMAIL), err)
//     CHECK_OK(read_response(sock, buffer), err)
//     CHECK_OK(send_command(sock, "RCPT TO: <%s>\n", email), err)
//     CHECK_OK(read_response(sock, buffer), err)

struct fd_sets {
    int nfds;
    fd_set read_fds;
    fd_set write_fds;
};

auto tuposoft::vrf::get_mx_records(const std::string &domain) -> std::vector<std::string> {
    ares_library_init(ARES_LIB_INIT_ALL);
    ares_channel channel{};
    fd_sets fds{};

    ares_options options{
            .sock_state_cb =
                    +[](void *data, const ares_socket_t socket_fd, const int readable, const int writable) {
                        const auto c = static_cast<fd_sets *>(data);
                        if (readable) {
                            FD_SET(socket_fd, &c->read_fds);
                        } else {
                            FD_CLR(socket_fd, &c->read_fds);
                        }

                        if (writable) {
                            FD_SET(socket_fd, &c->write_fds);
                        } else {
                            FD_CLR(socket_fd, &c->write_fds);
                        }

                        if (socket_fd >= c->nfds) {
                            c->nfds = socket_fd + 1;
                        } else {
                            auto empty{true};
                            for (auto i{0}; i < c->nfds; ++i) {
                                if (FD_ISSET(i, &c->read_fds) || FD_ISSET(i, &c->write_fds)) {
                                    empty = false;
                                    break;
                                }
                            }

                            if (empty) {
                                c->nfds = 0;
                            }
                        }
                    },
            .sock_state_cb_data = &fds,
    };

    std::vector<std::string> mx_records{};

    if (ares_init_options(&channel, &options, ARES_OPT_SOCK_STATE_CB) != ARES_SUCCESS) {
        return mx_records;
    }

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
            &mx_records, {});

    while (fds.nfds) {
        for (int i = 0; i < fds.nfds; ++i) {
            if (FD_ISSET(i, &fds.read_fds)) {
                ares_process_fd(channel, i, ARES_SOCKET_BAD);
            }
            if (FD_ISSET(i, &fds.write_fds)) {
                ares_process_fd(channel, ARES_SOCKET_BAD, i);
            }
        }
    }

    ares_destroy(channel);
    ares_destroy_options(&options);
    ares_library_cleanup();
    return mx_records;
}

auto tuposoft::vrf::operator<<(std::ostream &os, const verifier::data &data) -> decltype(os) {
    os << fmt::format("\nVerification summary:\n"
                      "email: {}\n"
                      "username: {}\n"
                      "domain: {}\n"
                      "mx_record: {}\n"
                      "result: {}\n"
                      "catch_all: {}\n\n",
                      data.email, data.username, data.domain, data.mx_record,
                      data.status == verifier::status::success ? "true" : "false",
                      data.status == verifier::status::catch_all_detected ? "true" : "false");

    return os;
}

auto tuposoft::vrf::verifier::check_mx(const std::string &mx_record, const std::string &email) -> int { 
	return {}; 
}

auto tuposoft::vrf::verifier::verify(const std::string &email) -> verifier::data { return {}; }
