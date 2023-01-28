//
// Created by Tuposoft Collective on 23.01.2023.
//

#include <arpa/nameser.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <stdarg.h>
#include "vrf.h"

static void
send_command(int sock, char *format, ...) {
    va_list args;
    va_start(args, format);
    char *command;
    vasprintf(&command, format, args);
    send(sock, command, strlen(command), 0);
    va_end(args);
    free(command);
}

static void
read_response(int sock, char *buffer) {
    char (*b)[SMTP_DATA_LINES_MAX_LENGTH] = (char (*)[SMTP_DATA_LINES_MAX_LENGTH]) buffer;
    if (read(sock, *b, sizeof *b) < 0) {
        printf("Failed to read from socket");
    }
    if (PRINT_RESPONSE) {
        printf("%s", (char *) b);
    }
}

static int
extract_local_part_and_domain(Vrf **result) {
    char *email = (*result)->email;
    char *at = email;
    while (*at && *at != '@') ++at;
    if (!*at) return EXIT_FAILURE;
    size_t local_part_size = at - email;
    (*result)->local_part = malloc(++local_part_size * sizeof *email);
    memcpy((*result)->local_part, email, at - email);
    size_t domain_size = strlen(email) - local_part_size;
    (*result)->domain = malloc(domain_size * sizeof *email);
    memcpy((*result)->domain, at + 1, domain_size);
    return EXIT_SUCCESS;
}

static int
get_mx_records(const char *name, char **mxs, int limit) {
    unsigned char response[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr;
    int mx_index, ns_index, len;
    char dispbuf[4096];

    if ((len = res_search(name, ns_c_in, ns_t_mx, response, sizeof response)) < 0) {
        return EXIT_FAILURE;
    }

    if (ns_initparse(response, len, &handle) < 0) {
        return EXIT_FAILURE;
    }

    len = ns_msg_count(handle, ns_s_an);
    if (len < 0)
        return EXIT_FAILURE;

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

    return EXIT_SUCCESS;
}

static int
check_mx(char *email, struct addrinfo *adrrinfo, Vrf **result) {
    int sock, client_fd;
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
        printf("Failed to create a socket.");
        return EXIT_FAILURE;
    }

    char buffer[SMTP_DATA_LINES_MAX_LENGTH];
    if ((client_fd = connect(sock, (struct sockaddr *) adrrinfo->ai_addr, sizeof(struct sockaddr))) < 0) {
        printf("Connection failed.");
        return EXIT_FAILURE;
    }
    read_response(sock, buffer);

    send_command(sock, "EHLO %s\n", CLIENT_MX);
    read_response(sock, buffer);
    send_command(sock, "MAIL FROM: <%s>\n", CLIENT_EMAIL);
    read_response(sock, buffer);
    send_command(sock, "RCPT TO: <%s>\n", email);
    read_response(sock, buffer);
    char status[4];
    memcpy(status, buffer, 3);
    status[3] = '\0';
    long code = strtol(status, NULL, 0);
    (*result)->result = code == 250;

    send_command(sock, "QUIT\n");
    close(client_fd);

    return EXIT_SUCCESS;
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
free_vrf(Vrf *result)
{
    free(result->email);
    free(result->local_part);
    free(result->domain);
    free(result->mx_record);
    free(result->mx_domain);
    free(result);
}

void
print_vrf(FILE *fd, Vrf *result)
{
    char *verdict;
    email_exists(result->result, result->catch_all, &verdict);

    fprintf(fd,
            "\nVerification summary:\n"
            "email: %s\n"
            "local part: %s\n"
            "domain: %s\n"
            "mx record: %s\n"
            "mx domain: %s\n"
            "result: %s\n"
            "catch_all: %s\n\n"
            "It means that this email %s exists!\n\n",
            result->email,
            result->local_part,
            result->domain,
            result->mx_record,
            result->mx_domain,
            result->result ? "true" : "false",
            result->catch_all ? "true" : "false",
            verdict
    );

    free(verdict);
}

int
verify(Vrf **result) {
    if (extract_local_part_and_domain(result) == EXIT_FAILURE) {
        printf("Email parts extraction failure.");
        return EXIT_FAILURE;
    }

    int mx_limit = 1;
    char **mxs = malloc(mx_limit * sizeof *mxs);
    if (get_mx_records("gmail.com", mxs, mx_limit) == EXIT_FAILURE) {
        printf("Failed to get MX records.");
        return EXIT_FAILURE;
    }
    (*result)->mx_record = mxs[0];

    struct addrinfo *adrrinfo;
    if (getaddrinfo(mxs[0], "smtp", NULL, &adrrinfo) > 0) {
        printf("Failed to get the IP.");
        return EXIT_FAILURE;
    }

    char *dummy;
    asprintf(&dummy, "%s@%s", CATCH_ALL_LOCAL_PART, (*result)->domain);
    if (check_mx(dummy, adrrinfo, result) == EXIT_SUCCESS) {
        (*result)->catch_all = (*result)->result;
    }

    if ((*result)->catch_all) return EXIT_SUCCESS;

    return check_mx((*result)->email, adrrinfo, result);
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: vrf <email>\n");
        return EXIT_FAILURE;
    }

    Vrf *result = malloc(sizeof *result);
    result->email = strdup(argv[1]);
    verify(&result);
    print_vrf(stdout, result);
    free_vrf(result);

    return 0;
}
