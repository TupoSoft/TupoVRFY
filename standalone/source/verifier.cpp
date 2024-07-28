#include "verifier.hpp"

#include "boost/beast.hpp"
#include "boost/url.hpp"
#include "cxxopts.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace url = boost::urls;
namespace tupovrf = tuposoft::tupovrf;

using tcp_stream = boost::beast::tcp_stream::rebind_executor<
    asio::use_awaitable_t<>::executor_with_default<asio::any_io_executor> >::other;

template<class Body, class Allocator>
auto handle_request(
    http::request<Body, http::basic_fields<Allocator> > request) -> asio::awaitable<http::message_generator> {
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
        co_return bad_request("Unknown HTTP method.");
    }

    const auto url = url::url_view{request.target()};
    const auto params = url.params();

    if (request.target().empty() or params.empty() or request.target().find("..") != std::string_view::npos) {
        co_return bad_request("Illegal request target.");
    }

    if (not params.contains("email")) {
        co_return bad_request("No email to verify!");
    }

    const auto email_param = params.find("email");
    if (not(*email_param).has_value) {
        co_return bad_request("The email parameter is empty!");
    }

    const auto email = (*email_param).value;

    auto verifier = tupovrf::verifier{co_await asio::this_coro::executor};
    co_await verifier.verify(email);

    auto response = http::response<http::string_body>{http::status::ok, request.version()};
    response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    response.set(http::field::content_type, "text/html");
    response.keep_alive(request.keep_alive());
    response.body() = (*email_param).value + '\n';
    response.prepare_payload();
    co_return response;
}

auto handle_session(tcp_stream stream) -> asio::awaitable<void> {
    auto buffer = beast::flat_buffer{};
    static constexpr auto STREAM_DURATION = 30;

    try {
        for (;;) {
            stream.expires_after(std::chrono::seconds(STREAM_DURATION));

            auto request = http::request<http::string_body>{};
            co_await http::async_read(stream, buffer, request);
            auto msg = co_await handle_request(std::move(request));
            const auto keep_alive = msg.keep_alive();

            co_await beast::async_write(stream, std::move(msg), asio::use_awaitable);

            if (!keep_alive) {
                break;
            }
        }
    } catch (boost::system::system_error &err) {
        if (err.code() != http::error::end_of_stream) {
            throw;
        }
    }

    stream.socket().shutdown(asio::ip::tcp::socket::shutdown_send);
};

auto listen(const asio::ip::tcp::endpoint endpoint) -> asio::awaitable<void> {
    auto acceptor = asio::use_awaitable_t<>::as_default_on(asio::ip::tcp::acceptor{co_await asio::this_coro::executor});
    acceptor.open(endpoint.protocol());
    acceptor.set_option(asio::socket_base::reuse_address(true));
    acceptor.bind(endpoint);
    acceptor.listen();

    auto verifier = std::make_shared<tupovrf::verifier>(co_await asio::this_coro::executor);

    for (;;) {
        co_spawn(acceptor.get_executor(), handle_session(tcp_stream(co_await acceptor.async_accept())),
                 [](const std::exception_ptr &e_ptr) {
                     if (e_ptr) {
                         try {
                             std::rethrow_exception(e_ptr);
                         } catch (std::exception &exc) {
                             std::cerr << "Error in session: " << exc.what() << "\n";
                         }
                     }
                 });
    }
};

auto main(const int argc, char *argv[]) -> int {
    try {
        auto options = cxxopts::Options{"Email Verifier", "The program to verify emails."};
        options.add_options()("h,host", "Host", cxxopts::value<std::string>()->default_value("0.0.0.0"))(
            "p,port", "Port", cxxopts::value<std::uint16_t>()->default_value("8080"))(
            "t,thread", "Thread count", cxxopts::value<int>()->default_value("1"));
        const auto result = options.parse(argc, argv);

        if (result.count("help") != 0U) {
            std::cout << options.help() << '\n';
            return EXIT_SUCCESS;
        }

        const auto host = result["host"].as<std::string>();
        const auto port = result["port"].as<std::uint16_t>();
        const auto thread_count = result["thread"].as<int>();

        auto io_context = asio::io_context{thread_count};

        co_spawn(io_context, listen(asio::ip::tcp::endpoint{asio::ip::address::from_string(host), port}),
                 [](const std::exception_ptr &exc) {
                     if (exc) {
                         try {
                             std::rethrow_exception(exc);
                         } catch (std::exception &exception) {
                             std::cerr << "Error in acceptor: " << exception.what() << "\n";
                         }
                     }
                 });

        auto threads = std::vector<std::thread>{};
        threads.reserve(thread_count - 1);
        for (auto i = thread_count - 1; i > 0; --i) {
            threads.emplace_back([&io_context] { io_context.run(); });
        }
        io_context.run();
    } catch (std::exception &e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
