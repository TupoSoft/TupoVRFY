#pragma once

#include "resolver.hpp"
#include "vrf_data.hpp"

#include "boost/asio.hpp"

namespace tuposoft::vrf {
    class verifier {
    public:
        explicit verifier(const asio::any_io_executor &executor) : resolv_(executor), socket_(executor) {
        }

        auto verify(std::string) -> asio::awaitable<vrf_data>;

    private:
        resolver resolv_;
        asio::ip::tcp::socket socket_;

        static constexpr auto SMTP_PORT = 25;
    };
}
