#include "test.hpp"

#include <iostream>
#include <future>
#include <string>
#include <string_view>
#include <mutex>

#include "client.h"
#include "server.h"
#include "color.hpp"

using namespace test;

namespace
{

constexpr uint16_t         kPort     = 4443;
constexpr std::string_view kCertPath = "cert.pem";
constexpr std::string_view kKeyPath  = "key.pem";
constexpr std::string_view kStopMsg  = "stop";

std::mutex  lock;
std::string expected_msg;

#define CLIENT_LOG (std::cout << cyellow("#client: "))
#define SERVER_LOG (std::cout << cmangenta("#server: "))

int run_client(std::string_view msg, srv_ans_handler_t handler)
{
    CLIENT_LOG << "setting the server expect '" << msg << "' message\n";
    std::unique_lock g(lock);
    expected_msg = msg;
    g.unlock();
    CLIENT_LOG << "running client that is sending '" << msg << "' message\n";
    return client(kCertPath.data(), "localhost", kPort, expected_msg.data(), handler);
}

cl_msg_handler_t global_cl_handler;

int cl_msg_handler(char const *msg)
{
    std::lock_guard g(lock);
    return global_cl_handler ? global_cl_handler(msg) : 0;
}

void reset_cl_msg_handler(cl_msg_handler_t handler = nullptr)
{
    std::lock_guard g(lock);
    global_cl_handler = handler;
}

int test_1_cl_msg_handler(char const *msg)
{
    SERVER_LOG << "Received msg from a client: '" << msg << "'\n";
    auto const verdict = EXPECT_STREQ(expected_msg.data(), msg, "Received incorrect client msg");
    if (verdict)
        SERVER_LOG << "msg received as expected one. Replying with success\n";
    else
        SERVER_LOG << "msg received is not as expected one. Replying with failure\n";
    return !verdict;
}

int test_2_cl_msg_handler(char const *msg)
{
    SERVER_LOG << "Received msg from a client: '" << msg << "'\n";
    SERVER_LOG << "Replying with failure\n";
    return 1;
}

void srv_msg_handler(char const *ans, char const *exp_ans)
{
    CLIENT_LOG << "Received answer from the server: " << ans << std::endl;
    auto const verdict = EXPECT_STREQ(exp_ans, ans, "Unexpected server reply");
    if (verdict)
        CLIENT_LOG << "server reply received as expected one\n";
    else
        CLIENT_LOG << "server reply received is not as expected one\n";
}

void srv_msg_check_ok_handler(char const *ans) { srv_msg_handler(ans, "ok"); }
void srv_msg_check_not_ok_handler(char const *ans) { srv_msg_handler(ans, "not ok"); }

} // anonymous namespace

int main(int argc, char *argv[])
{
    TEST(ServerRepliesWithSuccess, {
        reset_cl_msg_handler(test_1_cl_msg_handler);
        auto s = std::async([]{ return server(kCertPath.data(), kKeyPath.data(), kPort, cl_msg_handler); });
        auto c = std::async([]{ return run_client("Hello, world", srv_msg_check_ok_handler); });
        EXPECT_TRUE(!c.get(), "Client returned failed code");
        reset_cl_msg_handler();
        EXPECT_TRUE(!client(kCertPath.data(), "localhost", kPort, kStopMsg.data(), NULL), "Client returned non-zero code");
        EXPECT_TRUE(!s.get(), "Server returned failed code");
    });

    TEST(ServerRepliesWithFailure, {
        reset_cl_msg_handler(test_2_cl_msg_handler);
        auto s = std::async([]{ return server(kCertPath.data(), kKeyPath.data(), kPort, cl_msg_handler); });
        auto c = std::async([]{ return run_client("Hello, world", srv_msg_check_not_ok_handler); });
        EXPECT_TRUE(!c.get(), "Client returned failed code");
        reset_cl_msg_handler();
        EXPECT_TRUE(!client(kCertPath.data(), "localhost", kPort, kStopMsg.data(), NULL), "Client returned non-zero code");
        EXPECT_TRUE(!s.get(), "Server returned failed code");
    });

    return run_test_cases();
}
