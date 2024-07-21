//
// Created by Tuposoft Collective on 23.01.2023.
//

#pragma once

#include <string>

namespace tuposoft::vrf {
    auto extract_email_parts(const std::string &email) -> std::pair<std::string, std::string>;

    auto check_mx(const std::string &mx_record, const std::string &email) -> int;
} // namespace tuposoft::vrf
