#include "../include/Common.hpp"
#include "gtest/gtest.h"

TEST( Common, CountFormatSpecifiers1 )
{
    EXPECT_EQ( common::count_format_specifiers( "%" ), 0 );
}

TEST( Common, CountFormatSpecifiers2 )
{
    EXPECT_EQ( common::count_format_specifiers( "%s" ), 1 );
}

TEST( Common, CountFormatSpecifiers3 )
{
    EXPECT_EQ( common::count_format_specifiers( "Format %d %s %i" ), 3 );
}

TEST( Common, CountFormatSpecifiers4 )
{
    EXPECT_EQ( common::count_format_specifiers( "Format %d %%s %i" ), 2 );
}

TEST( Common, CountFormatSpecifiers5 )
{
    EXPECT_EQ( common::count_format_specifiers( "%" ), 0 );
}

TEST( Common, CountFormatSpecifiers6 )
{
    EXPECT_EQ( common::count_format_specifiers( "%%" ), 0 );
}

TEST( Common, CountFormatSpecifiers7 )
{
    EXPECT_EQ( common::count_format_specifiers( "" ), 0 );
}
