/**
 * Author:    Copilot
 * Created:   10.08.2026
 * Brief:     Compatibility tests for Expected.hpp
 **/

#include "Expected.hpp"

#include <gtest/gtest.h>
#include <string>

TEST( ExpectedCompat, StoresValue )
{
    const compat::expected<int, std::string> result{ 42 };
    ASSERT_TRUE( result.has_value() );
    EXPECT_EQ( *result, 42 );
}

TEST( ExpectedCompat, ConvertsCStringErrorsToString )
{
    const compat::expected<void, std::string> result{ compat::unexpected( "boom" ) };
    ASSERT_FALSE( result.has_value() );
    EXPECT_EQ( result.error(), "boom" );
}

TEST( ExpectedCompat, DistinguishesValueAndErrorWhenTypesMatch )
{
    const compat::expected<std::string, std::string> ok{ std::string{ "value" } };
    ASSERT_TRUE( ok.has_value() );
    EXPECT_EQ( *ok, "value" );

    const compat::expected<std::string, std::string> err{ compat::unexpected( "error" ) };
    ASSERT_FALSE( err.has_value() );
    EXPECT_EQ( err.error(), "error" );
}
