//
// Created by Tuposoft Collective on 23.01.2023.
//

#include "EmailVerification.hpp"
#include "asio/io_service.hpp"

#include <ares.h>
#include <asio.hpp>
#include <fmt/format.h>

#include <iostream>
#include <regex>
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
    static const auto email_regex = std::regex(R"((\w+[\w\.]*)@(\w+\.\w+))");

    if (auto matches = std::smatch(); std::regex_search(email, matches, email_regex)) {
        return {matches[1], matches[2]};
    }

    throw std::invalid_argument("Invalid email format");
}

// static VRF_err_t
// check_mx(char *email, struct addrinfo *adrrinfo, EmailVerificationData
// *result) {
//     int sock, client_fd;
//     if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
//         printf("Failed to create a socket.\n");
//         return VRF_ERR;
//     }
//
//     char buffer[SMTP_DATA_LINES_MAX_LENGTH];
//     if ((client_fd = connect(sock, (struct sockaddr *) adrrinfo->ai_addr,
//     sizeof(struct sockaddr))) < 0) {
//         printf("Connection failed.\n");
//         return VRF_ERR;
//     }
//
//     if (verbose) printf("SUCCESSFULLY CONNECTED TO %s\n",
//     (*result)->mx_record);
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

auto tuposoft::vrf::check_mx(const std::string &email, const std::string &mail_server) -> int {
    asio::io_service ios;
    asio::ip::tcp::resolver tcp_resolver(ios);
    asio::ip::tcp::resolver::query query(mail_server, "25");
    asio::ip::tcp::resolver::iterator endpoint_iterator = tcp_resolver.resolve(query);
    asio::ip::tcp::socket socket(ios);
    asio::error_code error = asio::error::host_not_found;

    while (error && endpoint_iterator != asio::ip::tcp::resolver::iterator()) {
        socket.close();
        socket.connect(*endpoint_iterator++, error);
    }
    if (error) {
        throw asio::system_error(error);
    }

    // Read the server's greeting message
    asio::streambuf response;
    asio::read_until(socket, response, "\n");

    // Send EHLO command
    std::string ehlo_cmd = "EHLO client.example.com\r\n";
    asio::write(socket, asio::buffer(ehlo_cmd), error);

    // Send MAIL FROM command
    std::string mail_from_cmd = "MAIL FROM:< example@example.com>\r\n";
    asio::write(socket, asio::buffer(mail_from_cmd), error);

    // Send RCPT TO command
    std::string rcpt_to_cmd = "RCPT TO:<" + email + ">\r\n";
    asio::write(socket, asio::buffer(rcpt_to_cmd), error);

    // Read the server's response
    asio::read_until(socket, response, "\n");

    // Check if the recipient is valid
    std::istream response_stream(&response);
    std::string server_response;
    std::getline(response_stream, server_response);

    return std::stoi(server_response);
}

auto tuposoft::vrf::verify(const std::string &email) -> vrf_data { return {}; }
