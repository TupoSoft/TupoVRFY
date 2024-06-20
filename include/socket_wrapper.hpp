#pragma once

#include <asio.hpp>

#include <string>

namespace tuposoft::vrf {
    struct basic_socket_wrapper {
        virtual ~basic_socket_wrapper() = default;
        virtual void connect(const std::string &host, const std::string &service) = 0;
        virtual std::size_t read(std::vector<std::byte> &) = 0;
        virtual std::size_t write(const std::string &message) = 0;
        virtual void close() = 0;
    };

    struct socket_wrapper final : basic_socket_wrapper {
        asio::io_context &io_context_;

        explicit socket_wrapper(asio::io_context &io_context) : io_context_{io_context} {};
        void connect(const std::string &host, const std::string &service) override;
        std::size_t read(std::vector<std::byte> &) override;
        std::size_t write(const std::string &message) override;
        void close() override;

    private:
        asio::ip::tcp::socket socket_{io_context_};
    };
}; // namespace tuposoft::vrf
