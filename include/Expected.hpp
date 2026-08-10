#pragma once

#if defined(__has_include)
#if __has_include(<expected>)
#include <expected>
#endif
#endif

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L

namespace compat
{
using std::expected;
using std::unexpected;
} // namespace compat

#else

#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace compat
{
template <class E> class unexpected
{
  public:
    using error_type = E;

    constexpr explicit unexpected( const E &error ) : m_error( error )
    {
    }

    constexpr explicit unexpected( E &&error ) : m_error( std::move( error ) )
    {
    }

    constexpr const E &error() const &
    {
        return m_error;
    }

    constexpr E &error() &
    {
        return m_error;
    }

    constexpr const E &&error() const &&
    {
        return std::move( m_error );
    }

    constexpr E &&error() &&
    {
        return std::move( m_error );
    }

  private:
    E m_error;
};

template <class E> unexpected( E ) -> unexpected<E>;

template <class T, class E> class expected
{
  public:
    using value_type = T;
    using error_type = E;

    constexpr expected( const T &value ) : m_storage( std::in_place_index<1>, value ), m_hasValue( true )
    {
    }

    constexpr expected( T &&value ) : m_storage( std::in_place_index<1>, std::move( value ) ), m_hasValue( true )
    {
    }

    template <class G> requires std::is_constructible_v<E, const G &>
    constexpr expected( const unexpected<G> &error ) : m_storage( std::in_place_index<2>, error.error() ),
                                                       m_hasValue( false )
    {
    }

    template <class G> requires std::is_constructible_v<E, G &&>
    constexpr expected( unexpected<G> &&error ) : m_storage( std::in_place_index<2>, std::move( error.error() ) ),
                                                  m_hasValue( false )
    {
    }

    constexpr expected( const expected & ) = default;
    constexpr expected( expected && ) noexcept = default;
    constexpr expected &operator=( const expected & ) = default;
    constexpr expected &operator=( expected && ) noexcept = default;
    ~expected() = default;

    constexpr bool has_value() const noexcept
    {
        return m_hasValue;
    }

    constexpr explicit operator bool() const noexcept
    {
        return m_hasValue;
    }

    constexpr T &value() &
    {
        return std::get<1>( m_storage );
    }

    constexpr const T &value() const &
    {
        return std::get<1>( m_storage );
    }

    constexpr T &&value() &&
    {
        return std::move( std::get<1>( m_storage ) );
    }

    constexpr const T &&value() const &&
    {
        return std::move( std::get<1>( m_storage ) );
    }

    constexpr E &error() &
    {
        return std::get<2>( m_storage );
    }

    constexpr const E &error() const &
    {
        return std::get<2>( m_storage );
    }

    constexpr E &&error() &&
    {
        return std::move( std::get<2>( m_storage ) );
    }

    constexpr const E &&error() const &&
    {
        return std::move( std::get<2>( m_storage ) );
    }

    constexpr T &operator*() &
    {
        return value();
    }

    constexpr const T &operator*() const &
    {
        return value();
    }

    constexpr T *operator->()
    {
        return &value();
    }

    constexpr const T *operator->() const
    {
        return &value();
    }

  private:
    std::variant<std::monostate, T, E> m_storage;
    bool m_hasValue{};
};

template <class E> class expected<void, E>
{
  public:
    using value_type = void;
    using error_type = E;

    constexpr expected() = default;

    template <class G> requires std::is_constructible_v<E, const G &>
    constexpr expected( const unexpected<G> &error ) : m_error( error.error() )
    {
    }

    template <class G> requires std::is_constructible_v<E, G &&>
    constexpr expected( unexpected<G> &&error ) : m_error( std::move( error.error() ) )
    {
    }

    constexpr expected( const expected & ) = default;
    constexpr expected( expected && ) noexcept = default;
    constexpr expected &operator=( const expected & ) = default;
    constexpr expected &operator=( expected && ) noexcept = default;
    ~expected() = default;

    constexpr bool has_value() const noexcept
    {
        return !m_error.has_value();
    }

    constexpr explicit operator bool() const noexcept
    {
        return has_value();
    }

    constexpr void value() const noexcept
    {
    }

    constexpr E &error() &
    {
        return *m_error;
    }

    constexpr const E &error() const &
    {
        return *m_error;
    }

    constexpr E &&error() &&
    {
        return std::move( *m_error );
    }

    constexpr const E &&error() const &&
    {
        return std::move( *m_error );
    }

  private:
    std::optional<E> m_error{};
};
} // namespace compat

#endif
