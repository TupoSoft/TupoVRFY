//
// Created by Tuposoft Collective on 23.01.2023.
//

#include "EmailVerification.hpp"

#include <vector>
#include <memory>
#include <format>

#ifndef FREE
#define FREE(p) free(p); p = NULL;
#endif

#define CHECK_OK(f, err)    \
if ((err = f) != VRF_OK) {  \
    return err;             \
}

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
    if (const size_t atPosition = email.find('@'); atPosition != std::string::npos) {
        std::string username = email.substr(0, atPosition);
        std::string domain = email.substr(atPosition + 1);
        return std::make_pair(username, domain);
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

std::string email_exists(const EmailVerificationResult &result) {
    if (result == EmailVerificationResult::CatchAllDetected) {
        return "may";
    }
    if (result == EmailVerificationResult::Success) {
        return "does";
    }

    return "doesn't";
}

auto printVerificationData(std::ostream &os, EmailVerificationData emailVerificationData) -> std::ostream & {
    // char *verdict;
    // email_exists(result.result, result->catch_all, &verdict);
    // if (!verdict) return VRF_ERR;
    // int err = fprintf(fd,
    //                   "\nVerification summary:\n"
    //                   "email: %s\n"
    //                   "local part: %s\n"
    //                   "domain: %s\n"
    //                   "mx record: %s\n"
    //                   "mx domain: %s\n"
    //                   "result: %s\n"
    //                   "catch_all: %s\n\n"
    //                   "It means that this email %s exist!\n\n",
    //                   result->email,
    //                   result->local_part,
    //                   result->domain,
    //                   result->mx_record,
    //                   result->mx_domain,
    //                   result->result ? "true" : "false",
    //                   result->catch_all ? "true" : "false",
    //                   verdict
    // );

    os << std::format("\nVerification summary:\n"
                      "email: {}\n"
                      "local part: {}\n"
                      "domain: {}\n"
                      "mx record: {}\n"
                      "mx domain: {}\n"
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

    addrinfo *mxRecordInfoList;
    if (getaddrinfo(domain.c_str(), SMTP_SERVICE, &addrinfoHints, &mxRecordInfoList)) {
        throw std::runtime_error("Failed to get address info for domain: " + domain);
    }

    const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> mxRecordInfos(mxRecordInfoList, freeaddrinfo);

    std::vector<std::string> recordAddresses;
    for (const addrinfo *mxRecordInfo = mxRecordInfos.get(); mxRecordInfo != nullptr;
         mxRecordInfo = mxRecordInfo->ai_next) {
        char address[INET6_ADDRSTRLEN];
        getnameinfo(mxRecordInfo->ai_addr, static_cast<socklen_t>(mxRecordInfo->ai_addrlen), address, sizeof(address),
                    nullptr, 0, NI_NUMERICHOST);

        recordAddresses.emplace_back(address);
    }

    return recordAddresses;
}

// auto verify(const std::string &email) -> EmailVerificationData {
//     EmailVerificationData emailVerificationData;
//
//     std::tie(emailVerificationData.username, emailVerificationData.domain) = extractLocalPartAndDomain(email);
//     const auto mxRecords = getMXRecords(emailVerificationData.domain);
//     emailVerificationData.mxRecord = mxRecords.at(0);
//
//     char *dummy;
//     asprintf(&dummy, "%s@%s", CATCH_ALL_LOCAL_PART, (*result)->domain);
//     if ((err = check_mx(dummy, adrrinfo, result)) != VRF_OK) {
//         return err;
//     }
//     (*result)->catch_all = (*result)->result;
//     if ((*result)->catch_all) return VRF_OK;
//
//     if ((err = check_mx((*result)->email, adrrinfo, result)) != VRF_OK) {
//         return err;
//     }
//
//     return emailVerificationData;
// }

int main(const int argc, char **argv) {
#ifdef _WIN32
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        std::cerr << "Winsock failed to initialize." << std::endl;
        return EXIT_FAILURE;
    }
#endif


    if (argc < 2) {
        fprintf(stderr, "Usage: %s [OPTIONS].\n", argv[0]);
        return EXIT_FAILURE;
    }

    std::string email;
    bool emailflag = false;
    bool verboseflag = false;

    int c;
    while ((c = getopt(argc, argv, "e:v")) != -1) {
        switch (c) {
            case 'e':
                email = optarg;
                emailflag = true;
                break;
            case 'v':
                verboseflag = true;
                break;
            default:
                break;
        }
    }

    verbose = verboseflag;

    if (!emailflag) {
        fprintf(stderr, "-e flag is required.\n");
        return EXIT_FAILURE;
    }

    try {
        const EmailVerificationData emailVerificationData = verify(email);
        printVerificationData(std::cout, emailVerificationData);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return EXIT_SUCCESS;
}
