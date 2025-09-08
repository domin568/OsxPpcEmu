/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/

#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include <LIEF/MachO.hpp>
#include <bit>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>

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

bool CMachoLoader::mapMemory( uc_engine *uc )
{
    for (const auto &seg : m_executable->segments())
    {
        uc_err err{ uc_mem_map( uc, seg.virtual_address(), seg.virtual_size(), seg.max_protection() ) };
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
            err = uc_mem_write( uc, seg.virtual_address(), seg.data().data(), seg.data().size_bytes() );
            if (err != UC_ERR_OK)
            {
                std::cerr << "SEGMENT: " << seg.name() << " could not be written to unicorn" << std::endl;
                return false;
            }
        }
    }
    return true;
}

bool CMachoLoader::setUnixThread( uc_engine *uc )
{
    if (!m_executable->has_thread_command())
        return false;

    if (m_executable->thread_command()->flavor() != Ppc_Thread_State)
        return false;

    ppc_thread_state32_t st{
        ppc_thread_state32_t::from_bytes( m_executable->thread_command()->state(), std::endian::big ) };

    uc_err err{};
    // entrypoint
    err = uc_reg_write( uc, UC_PPC_REG_PC, &st.srr0 ); // SRR0 save/restore register 0
    err = uc_reg_write( uc, UC_PPC_REG_XER, &st.cr );
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

    return true;
}