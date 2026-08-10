/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Unicorn hook callbacks
 **/
#pragma once

#include "Expected.hpp"
#include "HookContext.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <unicorn/unicorn.h>

namespace emu::hooks
{

// unicorn hook callbacks
void hook_api( uc_engine *uc, std::uint64_t address, std::uint32_t size, void *user_data );
void hook_intr( uc_engine *uc, std::uint32_t intno, void *user_data );
bool hook_mem_invalid( uc_engine *uc, uc_mem_type type, std::uint64_t address, int size, std::int64_t value,
                       void *user_data );
#ifdef DEBUGGER_ENABLED
void hook_debug( uc_engine *uc, std::uint64_t address, std::uint32_t size, void *user_data );
void hook_watchpoint( uc_engine *uc, uc_mem_type type, std::uint64_t address, int size, std::int64_t value,
                      void *user_data );
#endif

enum class HookId : std::size_t
{
    Api = 0,
    Interrupt,
    MemInvalid,
#ifdef DEBUGGER_ENABLED
    Debug,
    Watchpoint,
#endif
    Count,
};

class CHookManager
{
  public:
    CHookManager() = default;
    ~CHookManager();
    CHookManager( const CHookManager & ) = delete;
    CHookManager &operator=( const CHookManager & ) = delete;
    CHookManager( CHookManager &&other ) noexcept;
    CHookManager &operator=( CHookManager &&other ) noexcept;

    compat::expected<void, std::string> install_all( HookContext &ctx, std::uint64_t textStart, std::uint64_t textEnd );

  private:
    static constexpr std::size_t Hook_Count{ static_cast<std::size_t>( HookId::Count ) };

    HookContext *m_ctx{ nullptr };
    std::array<uc_hook, Hook_Count> m_handles{};
    std::array<bool, Hook_Count> m_installed{};

    compat::expected<void, std::string> install( HookId id, int type, void *callback, std::uint64_t begin,
                                              std::uint64_t end, std::string_view name );
    void teardown();
};

} // namespace emu::hooks
