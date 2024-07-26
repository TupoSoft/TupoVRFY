#include "verifier.hpp"

#include "boost/beast.hpp"
#include "boost/url.hpp"

#include <span>

namespace http = beast::http;
namespace tupovrf = tuposoft::tupovrf;

using tcp_stream = beast::tcp_stream::rebind_executor<
        asio::use_awaitable_t<>::executor_with_default<asio::any_io_executor>>::other;

template<class Body, class Allocator>
auto handle_request(http::request<Body, http::basic_fields<Allocator>> &&request) {
    const auto bad_request = [&request](const std::string_view why) {
        auto response = http::response<http::string_body>{http::status::bad_request, request.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, "text/html");
        response.keep_alive(request.keep_alive());
        response.body() = std::string{why};
        response.prepare_payload();
        return response;
    };

    const auto not_found = [&request](const std::string_view target) {
        auto response = http::response<http::string_body>{http::status::not_found, request.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, "text/html");
        response.keep_alive(request.keep_alive());
        response.body() = "The resource " + std::string{target} + " was not found!";
        response.prepare_payload();
        return response;
    };

    const auto server_error = [&request](const std::string_view what) {
        auto response = http::response<http::string_body>{http::status::internal_server_error, request.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, "text/html");
        response.keep_alive(request.keep_alive());
        response.body() = "An error occurred: " + std::string{what};
        response.prepare_payload();
        return response;
    };

    if (request.method() != http::verb::get) {
        return bad_request("Unknown HTTP method.");
    }

    const auto url = url_view{request.target()};
    const auto params = url.params();

    if (request.target().empty() or params.empty() or request.target().find("..") != std::string_view::npos) {
        return bad_request("Illegal request target.");
    }

    if (not params.contains("email")) {
        return bad_request("No email to verify!");
    }

    const auto email_param = params.find("email");
    if (not(*email_param).has_value) {
        return bad_request("The email parameter is empty!");
    }

    const auto email_value = (*email_param).value;
}

auto handle_session(tcp_stream stream) -> asio::awaitable<void> {
    auto buffer = beast::flat_buffer{};
    static constexpr auto STREAM_DURATION = 30;

    try {
        for (;;) {
            stream.expires_after(std::chrono::seconds(STREAM_DURATION));

            auto request = http::request<http::string_body>{};
            co_await http::async_read(stream, buffer, request);
        }
    } catch (std::exception &e) {
        std::cerr << "Error: " << e.what() << '\n';
    }
};

auto listen(const asio::ip::tcp::endpoint endpoint) -> asio::awaitable<void> {
    auto acceptor = asio::use_awaitable_t<>::as_default_on(asio::ip::tcp::acceptor{co_await asio::this_coro::executor});
    acceptor.open(endpoint.protocol());
    acceptor.set_option(asio::socket_base::reuse_address(true));
    acceptor.bind(endpoint);
    acceptor.listen();
};

auto main(const int argc, char *argv[]) -> int {
    const auto args = std::span{argv, static_cast<std::size_t>(argc)};

    if (args.size() != 4) {
        std::cerr << "Usage: verifier <address> <port> <threads>\n"
                  << "Example:\n"
                  << "    verifier 0.0.0.0 8080 1\n";
    }

    const auto address = asio::ip::make_address(args[1]);

    const auto *port_cstr = args[2];
    char *end = nullptr;
    const auto port = static_cast<std::uint16_t>(std::strtoul(port_cstr, &end, 0));

    end = nullptr;
    const auto *threads_cstr = args[3];
    const auto threads = std::max(1, static_cast<const int>(std::strtoul(threads_cstr, &end, 0)));

    auto io_context = asio::io_context{threads};

    return 0;
}
