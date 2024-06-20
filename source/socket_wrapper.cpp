//
// Created by KK on 6/11/2024.
//

#include <../include/socket_wrapper.hpp>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include "asio/buffer.hpp"

using namespace tuposoft::vrf;
using tcp = asio::ip::tcp;

void socket_wrapper::connect(const std::string &host, const std::string &service) {
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

std::size_t socket_wrapper::read(std::vector<std::byte> &buffer) {
    auto ec = asio::error_code();
    auto read_len = socket_.read_some(asio::buffer(buffer.data(), buffer.size()), ec);
    if (ec) {
        throw std::runtime_error(ec.message());
    }

    return read_len;
}

std::size_t socket_wrapper::write(const std::string &message) {
    auto ec = asio::error_code();
    auto write_len = socket_.write_some(asio::buffer(message.data(), message.size()), ec);
    if (ec) {
        throw std::runtime_error(ec.message());
    }

    return write_len;
}

void socket_wrapper::close() { socket_.close(); }
