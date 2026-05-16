/**
 * Author:    domin568
 * Created:   13.05.2026
 * Brief:     Context for each shim (redirected API)
 **/

#pragma once
#include "CMachoLoader.hpp"
#include "CMemory.hpp"
#include <iostream>
#include <unicorn/unicorn.h>

struct ShimContext
{
    uc_engine *uc{};
    memory::CMemory *mem{};
    loader::CMachoLoader *loader{};

    template <std::size_t I, template <typename> class Pred, typename... Ts> struct count_before;
    template <std::size_t I, template <typename> class Pred> struct count_before<I, Pred>
    {
        static constexpr std::size_t value = 0;
    };
    template <std::size_t I, template <typename> class Pred, typename First, typename... Rest>
    struct count_before<I, Pred, First, Rest...>
    {
        static constexpr std::size_t value =
            I == 0 ? 0 : ( ( Pred<First>::value ? 1u : 0u ) + count_before<I - 1, Pred, Rest...>::value );
    };

    template <typename T> using IsGprArg = std::bool_constant<std::is_integral_v<T> || std::is_pointer_v<T>>;
    template <typename T> using IsFprArg = std::bool_constant<std::is_floating_point_v<T>>;

    template <typename T> std::optional<T> read_argument( const uc_ppc_reg regId )
    {
        uint64_t reg{};
        if (uc_reg_read( uc, regId, &reg ) != UC_ERR_OK)
        {
            std::cerr << "Could not read argument" << std::endl;
            return {};
        }
        if constexpr (std::is_integral_v<T>)
            return static_cast<T>( reg );
        else if constexpr (std::is_pointer_v<T>)
            return reinterpret_cast<T>( mem->get( reg ) );
        else if constexpr (std::is_same_v<T, double>)
            return std::bit_cast<double>( reg );
        else if constexpr (std::is_same_v<T, float>)
            return std::bit_cast<float>( static_cast<uint32_t>( reg ) );
        return {};
    }

    template <typename... Args, std::size_t... I>
    std::optional<std::tuple<Args...>> read_arguments_idx( std::index_sequence<I...> )
    {
        auto opts{ std::make_tuple( ( [this]<std::size_t idx, typename T>() -> std::optional<T> {
            if constexpr (IsGprArg<T>::value)
            {
                constexpr std::size_t offset{ count_before<idx, IsGprArg, Args...>::value };
                constexpr uc_ppc_reg base{ UC_PPC_REG_3 };
                return read_argument<T>( static_cast<uc_ppc_reg>( base + offset ) );
            }
            else if constexpr (IsFprArg<T>::value)
            {
                constexpr std::size_t offset{ count_before<idx, IsFprArg, Args...>::value };
                constexpr uc_ppc_reg base{ UC_PPC_REG_FPR1 };
                return read_argument<T>( static_cast<uc_ppc_reg>( base + offset ) );
            }
            return std::optional<T>{};
        }.template operator()<I, std::tuple_element_t<I, std::tuple<Args...>>>() )... ) };

        const bool ok{ ( ... && static_cast<bool>( std::get<I>( opts ) ) ) };
        if (!ok)
            return {};
        return std::make_optional( std::make_tuple( ( *std::get<I>( opts ) )... ) );
    }

    template <typename... Args> std::optional<std::tuple<Args...>> get_arguments()
    {
        return read_arguments_idx<Args...>( std::index_sequence_for<Args...>{} );
    }

    bool ret( std::uint32_t value ) const
    {
        if (uc_reg_write( uc, UC_PPC_REG_3, &value ) != UC_ERR_OK)
        {
            std::cerr << "Could not write return value" << std::endl;
            return false;
        }
        return true;
    }
};