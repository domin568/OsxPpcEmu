/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Unicorn hook callbacks + table-driven install/teardown
 **/
#include "EmuHooks.hpp"
#include "Common.hpp"
#include "EmuTrace.hpp"
#include "ImportDispatch.hpp"
#include "shims/ShimContext.hpp"

#include <sstream>
#include <utility>

namespace emu::hooks
{

void hook_api( uc_engine *uc, std::uint64_t address, std::uint32_t size, void *user_data )
{
    (void)size;
    auto *ctx{ static_cast<HookContext *>( user_data ) };
    const std::size_t idx{ ( address - common::Import_Dispatch_Table_Address ) >> import::Import_Entry_Size_Pow2 };
#ifdef DEBUGGER_ENABLED
    ctx->lastApiAddress = static_cast<std::uint32_t>( address );
    const bool traceThis{ idx == 0 || ( ctx->debugger && ctx->debugger->is_trace_mode() ) };
    if (traceThis)
        emu::trace::print_api_call_source( *ctx, uc, address, idx );
#endif
    ShimContext shimCtx{ uc, ctx->mem, ctx->loader };
    if (idx > 0)
        import::Import_Items[idx - import::Unknown_Import_Shift].hook( shimCtx ); // call API dispatch function
#ifdef DEBUGGER_ENABLED
    if (traceThis)
        emu::trace::print_api_return( *ctx, uc, idx );
#endif
}

void hook_intr( uc_engine *uc, std::uint32_t intno, void *user_data )
{
    auto *ctx{ static_cast<HookContext *>( user_data ) };
    emu::trace::print_interrupt( *ctx, uc, intno );
}

bool hook_mem_invalid( uc_engine *uc, uc_mem_type type, std::uint64_t address, int size, std::int64_t value,
                       void *user_data )
{
    auto *ctx{ static_cast<HookContext *>( user_data ) };
    emu::trace::print_mem_violation( *ctx, uc, type, address, size, value );
    return false;
}

#ifdef DEBUGGER_ENABLED

void hook_debug( uc_engine *uc, std::uint64_t address, std::uint32_t size, void *user_data )
{
    (void)size;
    auto *ctx{ static_cast<HookContext *>( user_data ) };
    if (!ctx->debugger || !ctx->debugger->is_active())
        return;

    const bool gdbActive{ ctx->gdbServer && ctx->gdbServer->is_running() };

    if (ctx->debugger->should_break( static_cast<std::uint32_t>( address ) ))
    {
        if (gdbActive)
        {
            if (ctx->gdbServer->is_execution_stopped())
            {
                ctx->gdbServer->wait_for_continue();
                return;
            }

            if (ctx->debugger->is_breakpoint( static_cast<std::uint32_t>( address ) ))
                ctx->gdbServer->notify_breakpoint( static_cast<std::uint32_t>( address ) );
            else
                ctx->gdbServer->notify_step_complete( static_cast<std::uint32_t>( address ) );

            ctx->gdbServer->wait_for_continue();
        }
        else
        {
            ctx->debugger->interactive_prompt();
        }
    }
}

void hook_watchpoint( uc_engine *uc, uc_mem_type type, std::uint64_t address, int size, std::int64_t value,
                      void *user_data )
{
    (void)uc;
    // Only interested in writes
    if (type != UC_MEM_WRITE && type != UC_MEM_WRITE_UNMAPPED && type != UC_MEM_WRITE_PROT)
        return;

    auto *ctx{ static_cast<HookContext *>( user_data ) };
    if (!ctx->debugger)
        return;

    if (ctx->debugger->check_watchpoint_write( static_cast<std::uint32_t>( address ), static_cast<std::size_t>( size ),
                                               static_cast<std::uint64_t>( value ) ))
    {
        const bool gdbActive{ ctx->gdbServer && ctx->gdbServer->is_running() };
        if (gdbActive)
        {
            ctx->gdbServer->notify_breakpoint( static_cast<std::uint32_t>( address ) );
            ctx->gdbServer->wait_for_continue();
        }
        else
        {
            ctx->debugger->interactive_prompt();
        }
    }
}

#endif

// ── CHookManager ─────────────────────────────────────────────────────────

CHookManager::~CHookManager()
{
    teardown();
}

CHookManager::CHookManager( CHookManager &&other ) noexcept
    : m_ctx{ std::exchange( other.m_ctx, nullptr ) }, m_handles{ other.m_handles }, m_installed{ other.m_installed }
{
    other.m_installed.fill( false );
}

CHookManager &CHookManager::operator=( CHookManager &&other ) noexcept
{
    if (this != &other)
    {
        teardown();
        m_ctx = std::exchange( other.m_ctx, nullptr );
        m_handles = other.m_handles;
        m_installed = other.m_installed;
        other.m_installed.fill( false );
    }
    return *this;
}

void CHookManager::teardown()
{
    if (!m_ctx || !m_ctx->uc)
        return;
    for (std::size_t i{ 0 }; i < Hook_Count; ++i)
    {
        if (m_installed[i])
            uc_hook_del( m_ctx->uc, m_handles[i] );
        m_installed[i] = false;
    }
}

std::expected<void, std::string> CHookManager::install( HookId id, int type, void *callback, std::uint64_t begin,
                                                        std::uint64_t end, std::string_view name )
{
    const std::size_t i{ static_cast<std::size_t>( id ) };
    const uc_err err{ uc_hook_add( m_ctx->uc, &m_handles[i], type, callback, m_ctx, begin, end ) };
    if (err != UC_ERR_OK)
    {
        std::ostringstream oss;
        oss << "could not install " << name << " hook: uc_err=" << static_cast<int>( err );
        return std::unexpected( oss.str() );
    }
    m_installed[i] = true;
    return {};
}

std::expected<void, std::string> CHookManager::install_all( HookContext &ctx, std::uint64_t textStart,
                                                            std::uint64_t textEnd )
{
    m_ctx = &ctx; // TODO COsxPpcEmu is moved at least once, need to fix that

    struct HookSpec
    {
        HookId id;
        int type;
        void *callback;
        std::uint64_t begin;
        std::uint64_t end;
        std::string_view name;
    };

    const std::array<HookSpec, Hook_Count> specs{ {
        { HookId::Api, UC_HOOK_CODE, reinterpret_cast<void *>( hook_api ), common::Import_Dispatch_Table_Address,
          common::Import_Dispatch_Table_Address + import::Import_Table_Size, "API" },
        { HookId::Interrupt, UC_HOOK_INTR, reinterpret_cast<void *>( hook_intr ), textStart, textEnd, "interrupt" },
        { HookId::MemInvalid, UC_HOOK_MEM_INVALID, reinterpret_cast<void *>( hook_mem_invalid ), 1, 0,
          "memory-invalid" },
#ifdef DEBUGGER_ENABLED
        { HookId::Debug, UC_HOOK_CODE, reinterpret_cast<void *>( hook_debug ), textStart, textEnd, "debug" },
        { HookId::Watchpoint, UC_HOOK_MEM_WRITE, reinterpret_cast<void *>( hook_watchpoint ), 1, 0, "watchpoint" },
#endif
    } };

    for (const auto &spec : specs)
    {
        if (auto res{ install( spec.id, spec.type, spec.callback, spec.begin, spec.end, spec.name ) }; !res)
            return res;
    }
    return {};
}

} // namespace emu::hooks
