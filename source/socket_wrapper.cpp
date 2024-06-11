//
// Created by KK on 6/11/2024.
//

#include <../include/socket_wrapper.hpp>
#include <iostream>

using namespace tuposoft::vrf;
using tcp = asio::ip::tcp;

void socket_wrapper::connect(const std::string host, const std::string service) {
    const auto query = tcp::resolver::query{host, service};
    auto resolver = tcp::resolver{io_context_};
    auto it = resolver.resolve(query);
    asio::error_code error = asio::error::host_not_found;

    while (error && !it.empty()) {
        close();
        if (auto ec = socket_.connect(*it++, error)) {
            std::cout << "Error occurred: " << ec.message() << '\n';
        }
    }
    if (error) {
        throw asio::system_error(error);
    }
}

std::size_t socket_wrapper::read_until(char delimiter) { return {}; }

std::size_t socket_wrapper::write(std::string message) { return {}; }

void socket_wrapper::close() {}
