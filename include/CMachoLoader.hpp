/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/
#pragma once
#include "../include/Common.hpp"
#include <LIEF/MachO.hpp>
#include <expected>
#include <flat_map>
#include <optional>
#include <unicorn/unicorn.h>

namespace loader
{

struct Error
{
    enum Type
    {
        FileNotFound,
        FatMacho,
        NotPowerPc,
        Missing_Dynamic_Bind_Command,
        Bad_Indirect_Symbols,
        Bad_Dyld_Section,
    };
    Type type;
    std::string message{};
};

class CMachoLoader
{
  public:
    enum class SymbolSection
    {
        TEXT,
    };

    static std::expected<CMachoLoader, Error> init( const std::string &path );
    bool map_image_memory( uc_engine *uc );
    bool set_unix_thread( uc_engine *uc );
    std::expected<std::vector<std::pair<std::string, std::pair<uint32_t, common::ImportType>>>, Error> get_imports();
    uint32_t get_ep();
    std::optional<std::pair<uint64_t, uint64_t>> get_text_segment_va_range();
    std::optional<std::string> get_symbol_name_for_va( const uint32_t va, LIEF::MachO::Symbol::TYPE type,
                                                       SymbolSection section );
    std::optional<LIEF::MachO::Section> get_section_for_va( const uint32_t va );

  private:
    explicit CMachoLoader( std::unique_ptr<LIEF::MachO::Binary> executable );

    static constexpr size_t Max_Segment_File_Size{ 32u * 1024 * 1024 };
    static constexpr size_t Ppc_Thread_State{ 1 };
    static constexpr size_t Dyld_Section_Symbol_Count{ 2 };
    static constexpr std::string Non_Lazy_Symbols_Ptr_Section_Name{ "__nl_symbol_ptr" };
    static constexpr std::string Lazy_Symbols_Ptr_Section_Name{ "__la_symbol_ptr" };
    static constexpr std::string Dyld_Symbol_Ptr_Section_Name{ "__dyld" };
    static constexpr std::string Text_Segment_Name{ "__TEXT" };

    static inline const std::unordered_map<SymbolSection, std::string> Symbol_Section_Name{ {
        { SymbolSection::TEXT, "__text" },
    } };

    uint32_t m_ep{};
    std::unique_ptr<LIEF::MachO::Binary> m_executable;

    // initialize functions
    static std::optional<LIEF::MachO::SegmentCommand> get_text_segment( LIEF::MachO::Binary &executable );
};
} // namespace loader