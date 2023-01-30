//
// Created by Tuposoft Collective on 23.01.2023.
//

#include <arpa/nameser.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include "vrf.h"

#ifndef FREE
#define FREE(p) free(p); p = NULL;
#endif

#define CHECK_OK(f, err)    \
if ((err = f) != VRF_OK) {  \
    return err;             \
}

struct
VRF {
    char *email;
    char *local_part;
    char *domain;
    char *mx_record;
    char *mx_domain;
    bool result;
    bool catch_all;
};

static VRF_err_t
send_command(int sock, char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *command;
    if (vasprintf(&command, format, args) < 0) {
        return VRF_ERR;
    }
#if DEBUG_RESPONSE
    printf("REQUEST: %s", command);
#endif
    if (send(sock, command, strlen(command), 0) < 0) {
        return VRF_ERR;
    }
    va_end(args);
    free(command);

    return VRF_OK;
}

static VRF_err_t
read_response(int sock, char *buffer)
{
    char (*b)[SMTP_DATA_LINES_MAX_LENGTH] = (char (*)[SMTP_DATA_LINES_MAX_LENGTH]) buffer;
    ssize_t nbytes;
    if ((nbytes = read(sock, *b, sizeof *b)) < 0) {
        printf("Failed to read from socket.\n");
        return VRF_ERR;
    }

    #if DEBUG_RESPONSE
        printf("RESPONSE: %s", (char *) b);
    #endif

//    memset(*b, 0, nbytes);
    return VRF_OK;
}

static VRF_err_t
extract_local_part_and_domain(VRF *result)
{
    char *email = (*result)->email;
    char *at = email;
    while (*at && *at != '@') ++at;
    if (!*at) return VRF_ERR;
    size_t local_part_size = at - email;
    (*result)->local_part = malloc(++local_part_size * sizeof *email);
    memcpy((*result)->local_part, email, at - email);
    size_t domain_size = strlen(email) - local_part_size;
    (*result)->domain = malloc(domain_size * sizeof *email);
    memcpy((*result)->domain, at + 1, domain_size);
    return h_errno != ENOMEM ? VRF_OK : VRF_ERR;
}

static VRF_err_t
get_mx_records(const char *name, char **mxs, int limit)
{
    unsigned char response[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    int mx_index, ns_index, len;
    char dispbuf[4096];

    if ((len = res_search(name, ns_c_in, ns_t_mx, response, sizeof response)) < 0) {
        return VRF_ERR;
    }

    if (ns_initparse(response, len, &handle) < 0) {
        return VRF_ERR;
    }

    if ((len = ns_msg_count(handle, ns_s_an)) < 0) {
        return VRF_ERR;
    }

    for (mx_index = 0, ns_index = 0;
         mx_index < limit && ns_index < len;
         ns_index++) {
        if (ns_parserr(&handle, ns_s_an, ns_index, &rr)) {
            continue;
        }
        ns_sprintrr(&handle, &rr, NULL, NULL, dispbuf, sizeof dispbuf);
        if (ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_mx) {
            char mxname[NS_MAXDNAME];
            dn_expand(ns_msg_base(handle), ns_msg_base(handle) + ns_msg_size(handle), ns_rr_rdata(rr) + NS_INT16SZ,
                      mxname, sizeof mxname);
            mxs[mx_index++] = strdup(mxname);
        }
    }

    return VRF_OK;
}

static VRF_err_t
check_mx(char *email, struct addrinfo *adrrinfo, VRF *result)
{
    int sock, client_fd;
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
        printf("Failed to create a socket.\n");
        return VRF_ERR;
    }

    char buffer[SMTP_DATA_LINES_MAX_LENGTH];
    if ((client_fd = connect(sock, (struct sockaddr *) adrrinfo->ai_addr, sizeof(struct sockaddr))) < 0) {
        printf("Connection failed.\n");
        return VRF_ERR;
    }
    #if DEBUG_RESPONSE
        printf("SUCCESSFULLY CONNECTED TO %s\n", (*result)->mx_record);
    #endif

    int err;
    CHECK_OK(read_response(sock, buffer), err)
    CHECK_OK(send_command(sock, "EHLO %s\n", CLIENT_MX), err)
    CHECK_OK(read_response(sock, buffer), err)
    CHECK_OK(send_command(sock, "MAIL FROM: <%s>\n", CLIENT_EMAIL), err)
    CHECK_OK(read_response(sock, buffer), err)
    CHECK_OK(send_command(sock, "RCPT TO: <%s>\n", email), err)
    CHECK_OK(read_response(sock, buffer), err)
    char status[4];
    memcpy(status, buffer, 3);
    status[3] = '\0';
    long code = strtol(status, NULL, 0);
    if (!code) return VRF_ERR;
    (*result)->result = code == 250;

    CHECK_OK(send_command(sock, "QUIT\n"), err);

    return !close(client_fd) ? VRF_OK : VRF_ERR;
}

static void
email_exists(bool result, bool catch_all, char **verdict)
{
    if (catch_all) {
        *verdict = strdup("may");
    } else if (result) {
        *verdict = strdup("does");
    } else {
        *verdict = strdup("doesn't");
    }
}

void
free_vrf(VRF result)
{
    FREE(result->email);
    FREE(result->local_part);
    FREE(result->domain);
    FREE(result->mx_record);
    FREE(result->mx_domain);
    FREE(result);
}

VRF_err_t
print_vrf(FILE *fd, VRF result)
{
    char *verdict;
    email_exists(result->result, result->catch_all, &verdict);
    if (!verdict) return VRF_ERR;

    int err = fprintf(fd,
                      "\nVerification summary:\n"
                      "email: %s\n"
                      "local part: %s\n"
                      "domain: %s\n"
                      "mx record: %s\n"
                      "mx domain: %s\n"
                      "result: %s\n"
                      "catch_all: %s\n\n"
                      "It means that this email %s exist!\n\n",
                      result->email,
                      result->local_part,
                      result->domain,
                      result->mx_record,
                      result->mx_domain,
                      result->result ? "true" : "false",
                      result->catch_all ? "true" : "false",
                      verdict
    );

    FREE(verdict);

    return err < 0 ? VRF_ERR : VRF_OK;
}

VRF_err_t
verify(VRF *result)
{
    VRF_err_t err;
    if ((err = extract_local_part_and_domain(result)) != VRF_OK) {
        printf("Email parts extraction failure.\n");
        return err;
    }

    int mx_limit = 1;
    char **mxs = malloc(mx_limit * sizeof *mxs);
    if ((err = get_mx_records((*result)->domain, mxs, mx_limit)) != VRF_OK) {
        printf("Failed to get MX records.\n");
        return err;
    }
    (*result)->mx_record = mxs[0];

    struct addrinfo *adrrinfo;
    if (getaddrinfo(mxs[0], "smtp", NULL, &adrrinfo)) {
        printf("Failed to get the IP.\n");
        return VRF_ERR;
    }

    char *dummy;
    asprintf(&dummy, "%s@%s", CATCH_ALL_LOCAL_PART, (*result)->domain);
    if ((err = check_mx(dummy, adrrinfo, result)) != VRF_OK) {
        return err;
    }
    (*result)->catch_all = (*result)->result;
    if ((*result)->catch_all) return VRF_OK;

    if ((err = check_mx((*result)->email, adrrinfo, result)) != VRF_OK) {
        return err;
    }

    return VRF_OK;
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: vrf <email>\n");
        return EXIT_FAILURE;
    }

    int err;
    VRF result = malloc(sizeof *result);
    if (errno) return EXIT_FAILURE;
    if (!(result->email = strdup(argv[1]))) return EXIT_FAILURE;
    err = verify(&result);
    if (err == VRF_ERR) {
        free_vrf(result);
        return EXIT_FAILURE;
    }
    err = print_vrf(stdout, result);
    if (err == VRF_ERR) {
        free_vrf(result);
        return EXIT_FAILURE;
    }

    free_vrf(result);

    return EXIT_SUCCESS;
}
