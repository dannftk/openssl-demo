#pragma once

#include <cstdio>
#include <cstring>

#include <iostream>
#include <string>
#include <functional>
#include <utility>
#include <list>

#include "color.hpp"

namespace test
{

using test_t = std::pair<std::string, std::function<void()>>;

inline std::list<test_t> global_tests;
inline int global_status = 0;

#define EXPECT_TRUE(c, errmsg) \
    do { \
        if (!(c)) \
        { \
            std::cerr << (errmsg) << '\n'; \
            global_status = 1; \
        } \
    } while (false)

#define EXPECT_FALSE(c, errmsg) EXPECT_TRUE(!(c), (errmsg))

#define EXPECT_STREQ(s1, s2, errmsg) \
    ({ \
        bool r = true; \
        if (0 != strcmp((s1), (s2))) \
        { \
            std::cerr << cred((errmsg)) << '\n' << "expected: " << (s1) << "\n" << "got: " << (s2) << '\n'; \
            global_status = 1; \
            r = false; \
        } \
        r; \
    })

#define TEST(name, block) \
    do { global_tests.push_back({#name, [] block }); } while (false)

inline int run_test_cases()
{
    int status = 0;
    size_t passed = 0;
    for (auto const &t : global_tests)
    {
        std::cout << "Running TestCase '" << clgreen(t.first) << "'" << std::endl;
        t.second();
        status = status || global_status;
        if (!global_status)
        {
            ++passed;
            std::cout << "TestCase '" << clgreen(t.first) << "' " << cgreen("PASSED") << '\n' << std::endl;
        }
        else
        {
            std::cerr << "TestCase '" << clgreen(t.first) << "' " << cred("FAILED") << "\n\n";
        }
        global_status = 0;
    }

    std::cout << "All TestCases have completed\n";
    std::cout << cgreen("OVERALL") << ": " << global_tests.size() << ", ";
    std::cout << cgreen("PASSED")  << ": " << passed;
    if (passed < global_tests.size())
    {
        std::cout << ", ";
        std::cerr << cred("FAILED")  << ": " << global_tests.size() - passed << '\n';
    }
    else
    {
        std::cout << std::endl;
    }

    return status;
}

} // namespace test
