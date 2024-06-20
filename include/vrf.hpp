//
// Created by Tuposoft Collective on 23.01.2023.
//

#pragma once

#include <string>
#include <vector>

#include <socket_wrapper.hpp>

namespace tuposoft::vrf {
    class verifier {
    public:
        enum class status { success, invalid_email, failure, catch_all_detected, invalid_domain, mx_record_not_found };

        struct data {
            std::string email;
            std::string username;
            std::string domain;
            std::string mx_record;
            status status;
        };

        explicit verifier(std::unique_ptr<basic_socket_wrapper> socket) : socket_(std::move(socket)) {}

        friend auto operator<<(std::ostream &os, const data &data) -> decltype(os);

        auto verify(const std::string &email) -> data;

        auto check_mx(const std::string &mx_record, const std::string &email) -> int;

    private:
        std::unique_ptr<basic_socket_wrapper> socket_;
    };


    auto get_mx_records(const std::string &domain) -> std::vector<std::string>;

    auto extract_email_parts(const std::string &email) -> std::pair<std::string, std::string>;
} // namespace tuposoft::vrf
