/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/

#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include "../include/ImportDispatch.hpp"

#include <LIEF/MachO.hpp>
#include <bit>
#include <filesystem>
#include <flat_map>
#include <fstream>
#include <iostream>
#include <ranges>
#include <span>

static int translate_prot( uint32_t lief_prot )
{
    int prot = 0;
    // Example mapping — adapt to LIEF flags you see (vm_prot_t: R=1, W=2, X=4 usually)
    if (lief_prot & 0x1)
        prot |= UC_PROT_READ;
    if (lief_prot & 0x2)
        prot |= UC_PROT_WRITE;
    if (lief_prot & 0x4)
        prot |= UC_PROT_EXEC;
    return prot;
}

CMachoLoader::CMachoLoader( std::unique_ptr<LIEF::MachO::Binary> executable ) : m_executable( std::move( executable ) )
{
}

std::expected<CMachoLoader, common::Error> CMachoLoader::init( const std::string &path )
{
    if (!std::filesystem::exists( path ))
        return std::unexpected{ common::Error{ common::Error::Type::NotFound, "File not found." } };

    const LIEF::MachO::ParserConfig conf{ LIEF::MachO::ParserConfig::deep() };
    std::unique_ptr<LIEF::MachO::FatBinary> fat{ LIEF::MachO::Parser::parse( path, conf ) };

    if (fat->size() > 1)
        return std::unexpected{
            common::Error{ common::Error::Type::Unsupported, "FAT MachO binaries are not supported" } };

    std::unique_ptr<LIEF::MachO::Binary> ppcBinary{ fat->take( LIEF::MachO::Header::CPU_TYPE::POWERPC ) };
    if (!ppcBinary)
        return std::unexpected{
            common::Error{ common::Error::Type::Unsupported, "Only PowerPC binaries are supported." } };

    CMachoLoader loader{ std::move( ppcBinary ) };
    return loader;
}

bool CMachoLoader::map_image_memory( uc_engine *uc )
{
    for (const auto &seg : m_executable->segments())
    {
        uint64_t map_start = common::page_align_down( seg.virtual_address() );
        uint64_t map_end = common::page_align_up( seg.virtual_address() + seg.virtual_size() );
        uint64_t map_size = map_end - map_start;
        int perms = translate_prot( seg.max_protection() );

        uc_err err{ uc_mem_map( uc, map_start, map_size, perms ) };
        if (err != UC_ERR_OK)
        {
            std::cerr << "Error mapping memory from MachO file\n uc error:" << std::hex << "0x" << err << "\n -> "
                      << uc_strerror( err ) << "\n SEGMENT: " << seg.name() << std::endl;
            return false;
        }

        if (seg.file_size() > Max_Segment_File_Size)
        {
            std::cerr << "SEGMENT: " << seg.name() << " filesize is too big to map: " << std::hex << "0x"
                      << seg.file_size() << std::endl;
            return false;
        }

        if (seg.file_size() > 0)
        {
            err = uc_mem_write( uc, map_start, seg.content().data(), seg.content().size() );
            if (err != UC_ERR_OK)
            {
                std::cerr << "SEGMENT: " << seg.name() << " could not be written to unicorn" << std::endl;
                return false;
            }
        }
    }
    return true;
}

bool CMachoLoader::set_unix_thread( uc_engine *uc )
{
    if (!m_executable->has_thread_command())
        return false;

    if (m_executable->thread_command()->flavor() != Ppc_Thread_State)
        return false;

    common::ppc_thread_state32_t st{
        common::ppc_thread_state32_t::from_bytes( m_executable->thread_command()->state(), std::endian::big ) };

    uc_err err{};
    // entrypoint
    err = uc_reg_write( uc, UC_PPC_REG_PC, &st.srr0 ); // SRR0 save/restore register 0
    err = uc_reg_write( uc, UC_PPC_REG_CR, &st.cr );
    err = uc_reg_write( uc, UC_PPC_REG_XER, &st.xer );
    err = uc_reg_write( uc, UC_PPC_REG_LR, &st.lr );
    err = uc_reg_write( uc, UC_PPC_REG_CTR, &st.ctr );
    // MQ not present in unicorn
    // VRSAVE not present in unicorn
    // gpr
    err = uc_reg_write( uc, UC_PPC_REG_0, &st.r0 );
    err = uc_reg_write( uc, UC_PPC_REG_1, &st.r1 );
    err = uc_reg_write( uc, UC_PPC_REG_2, &st.r2 );
    err = uc_reg_write( uc, UC_PPC_REG_3, &st.r3 );
    err = uc_reg_write( uc, UC_PPC_REG_4, &st.r4 );
    err = uc_reg_write( uc, UC_PPC_REG_5, &st.r5 );
    err = uc_reg_write( uc, UC_PPC_REG_6, &st.r6 );
    err = uc_reg_write( uc, UC_PPC_REG_7, &st.r7 );
    err = uc_reg_write( uc, UC_PPC_REG_8, &st.r8 );
    err = uc_reg_write( uc, UC_PPC_REG_9, &st.r9 );
    err = uc_reg_write( uc, UC_PPC_REG_10, &st.r10 );
    err = uc_reg_write( uc, UC_PPC_REG_11, &st.r11 );
    err = uc_reg_write( uc, UC_PPC_REG_12, &st.r12 );
    err = uc_reg_write( uc, UC_PPC_REG_13, &st.r13 );
    err = uc_reg_write( uc, UC_PPC_REG_14, &st.r14 );
    err = uc_reg_write( uc, UC_PPC_REG_15, &st.r15 );
    err = uc_reg_write( uc, UC_PPC_REG_16, &st.r16 );
    err = uc_reg_write( uc, UC_PPC_REG_17, &st.r17 );
    err = uc_reg_write( uc, UC_PPC_REG_18, &st.r18 );
    err = uc_reg_write( uc, UC_PPC_REG_19, &st.r19 );
    err = uc_reg_write( uc, UC_PPC_REG_20, &st.r20 );
    err = uc_reg_write( uc, UC_PPC_REG_21, &st.r21 );
    err = uc_reg_write( uc, UC_PPC_REG_22, &st.r22 );
    err = uc_reg_write( uc, UC_PPC_REG_23, &st.r23 );
    err = uc_reg_write( uc, UC_PPC_REG_24, &st.r24 );
    err = uc_reg_write( uc, UC_PPC_REG_25, &st.r25 );
    err = uc_reg_write( uc, UC_PPC_REG_26, &st.r26 );
    err = uc_reg_write( uc, UC_PPC_REG_27, &st.r27 );
    err = uc_reg_write( uc, UC_PPC_REG_28, &st.r28 );
    err = uc_reg_write( uc, UC_PPC_REG_29, &st.r29 );
    err = uc_reg_write( uc, UC_PPC_REG_30, &st.r30 );
    err = uc_reg_write( uc, UC_PPC_REG_31, &st.r31 );
    if (err != UC_ERR_OK)
        return false;

    m_ep = st.srr0;
    return true;
}

// __nl_symbol_ptr and __la_symbol_ptr are sections that contains 4 byte addresses
// we want to overwrite all the pointers to point to our stub that dispatches all API calls
std::expected<std::vector<std::pair<std::string, std::pair<uint32_t, common::ImportType>>>, common::Error>
CMachoLoader::get_imports()
{
    std::vector<std::pair<std::string, std::pair<uint32_t, common::ImportType>>> imports{};

    if (!m_executable->has_dynamic_symbol_command())
        return std::unexpected{ common::Error{ common::Error::Type::Missing_Dynamic_Bind_Command_Error,
                                               "Missing Dynamic Bind Command needed to parse imports." } };

    for (const LIEF::MachO::Section &s : m_executable->sections())
    {
        if (s.name() == Non_Lazy_Symbols_Ptr_Section_Name || s.name() == Lazy_Symbols_Ptr_Section_Name)
        {
            if (s.size() == 0)
                continue;
            size_t symbolCount{ s.size() >> 2 }; // no alignment there
            uint32_t indirectSymbolsIdx{ s.reserved1() };
            if (indirectSymbolsIdx + symbolCount > m_executable->dynamic_symbol_command()->indirect_symbols().size())
                return std::unexpected{ common::Error{ common::Error::Type::Indirect_Symbols_Error,
                                                       "Indirect symbol idx is greater than indirect symbol size." } };

            const common::ImportType importType{ s.name() == Non_Lazy_Symbols_Ptr_Section_Name
                                                     ? common::ImportType::Indirect
                                                     : common::ImportType::Direct };
            for (size_t idx{ 0 }; idx < symbolCount; idx++)
            {
                const LIEF::MachO::Symbol importSymbol{
                    m_executable->dynamic_symbol_command()->indirect_symbols()[indirectSymbolsIdx + idx] };
                imports.push_back(
                    { importSymbol.name(), { s.virtual_address() + idx * sizeof( uint32_t ), importType } } );
            }
        }
        else if (s.name() == Dyld_Symbol_Ptr_Section_Name)
        {
            if (s.size() < 8)
                return std::unexpected{ common::Error{ common::Error::Type::Bad_Dyld_Section_Error,
                                                       "__dyld section should be at least 8 bytes in size." } };
            size_t symbolCount{ Dyld_Section_Symbol_Count };
            imports.push_back(
                { "_stub_binding_helper_ptr_in_dyld", { s.virtual_address(), common::ImportType::Direct } } );
            imports.push_back( { "_dyld_func_lookup_ptr_in_dyld",
                                 { s.virtual_address() + sizeof( uint32_t ), common::ImportType::Direct } } );
        }
    }
    return imports;
}

uint32_t CMachoLoader::get_ep()
{
    return m_ep;
}

std::optional<std::pair<uint64_t, uint64_t>> CMachoLoader::get_text_segment_va_range()
{
    const std::optional<LIEF::MachO::SegmentCommand> textSegment{ get_text_segment( *m_executable ) };
    if (!textSegment)
        return std::nullopt;
    return std::optional<std::pair<uint64_t, uint64_t>>(
        { textSegment->virtual_address(), textSegment->virtual_address() + textSegment->virtual_size() } );
}

std::optional<LIEF::MachO::SegmentCommand> CMachoLoader::get_text_segment( LIEF::MachO::Binary &executable )
{
    auto pred{ []( const LIEF::MachO::SegmentCommand &c ) { return c.name() == Text_Segment_Name; } };
    const auto textSegIt{ std::find_if( executable.segments().cbegin(), executable.segments().cend(), pred ) };
    if (textSegIt == executable.segments().cend())
        return std::nullopt;
    return *textSegIt;
}

std::optional<std::string> CMachoLoader::get_symbol_name_for_va( const uint32_t va, LIEF::MachO::Symbol::TYPE type,
                                                                 SymbolSection section )
{
    const auto secNameIt{ Symbol_Section_Name.find( section ) };
    if (secNameIt == Symbol_Section_Name.end())
        return std::nullopt;
    const std::string &sectionName{ secNameIt->second };

    auto sectMatches{ [&sectionName]( const LIEF::MachO::Section &s ) { return s.name() == sectionName; } };
    const auto sectIt{ std::find_if( m_executable->sections().begin(), m_executable->sections().end(), sectMatches ) };
    if (sectIt == m_executable->sections().end())
        return std::nullopt;
    if (va >= sectIt->virtual_address() + sectIt->size())
        return std::nullopt;

    std::map<uint32_t, std::string> symbolsByType{};
    for (const auto &s : m_executable->symbols())
    {
        if (s.type() != type)
            continue;
        symbolsByType[static_cast<uint32_t>( s.value() )] = s.name();
    }
    auto it{ symbolsByType.upper_bound( va ) };
    if (it == symbolsByType.begin())
        return std::nullopt;
    --it;
    return it->second;
}

std::optional<LIEF::MachO::Section> CMachoLoader::get_section_for_va( const uint32_t va )
{
    LIEF::MachO::Section *s{ m_executable->section_from_virtual_address( va ) };
    if (s == nullptr)
        return std::nullopt;
    return *s;
}