//
// Created by Tuposoft Collective on 23.01.2023.
//

#include "vrf.hpp"

#include <asio.hpp>
#include <fmt/format.h>

#include <iostream>
#include <regex>

using namespace tuposoft::vrf;

auto tuposoft::vrf::extract_email_parts(const std::string &email) -> std::pair<std::string, std::string> {
    static const auto email_regex = std::regex(R"((\w+[\w\.]*)@(\w+\.\w+))");

    if (auto matches = std::smatch(); std::regex_search(email, matches, email_regex)) {
        return {matches[1], matches[2]};
    }

    throw std::invalid_argument("Invalid email format");
}

struct fd_sets {
    int nfds;
    fd_set read_fds;
    fd_set write_fds;
};

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

auto tuposoft::vrf::check_mx(const std::string &mx_record, const std::string &email) -> int { return {}; }

auto tuposoft::vrf::verify(const std::string &email) -> vrf_data { return {}; }
