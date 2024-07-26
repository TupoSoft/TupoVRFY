#include "verifier.hpp"
#include "resolver.hpp"
#include "vrf.hpp"

#include "boost/regex.hpp"

#include <regex>

using namespace tuposoft::tupovrf;
using namespace boost::asio;

auto verifier::verify(const std::string email) -> awaitable<vrf_data> {
    auto [username, domain] = extract_email_parts(email);
    co_await resolv_.connect("1.1.1.1");
    const auto mx_records = co_await resolv_.query<dns_record_e::MX>(domain);
    const auto mx_record = co_await resolv_.query<dns_record_e::A>(mx_records.at(0).rdata.mx);
    co_await socket_.async_connect({ip::address::from_string(mx_record.at(0).rdata), SMTP_PORT}, use_awaitable);

    constexpr auto ehlo = "EHLO mail.tuposoft.com";
    co_await socket_.async_send(buffer(ehlo, strlen(ehlo)), use_awaitable);

    auto buf = streambuf{};
    co_await async_read_until(socket_, buf, regex{"220.*$"}, use_awaitable);

    co_return vrf_data{};
}
