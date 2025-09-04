/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/
#pragma once
#include <LIEF/MachO.hpp>
#include <expected>

class CMachoLoader
{
  public:
    struct Error
    {
        enum Type
        {
            NotFound,
            Unsupported
        };
        Type type;
        std::string message{};
    };

    static std::expected<CMachoLoader, Error> create( const std::string &path );

  private:
    explicit CMachoLoader( std::unique_ptr<LIEF::MachO::Binary> executable );
    static std::expected<CMachoLoader, Error> error( Error::Type type, const std::string &message );

    std::unique_ptr<LIEF::MachO::Binary> m_executable;
};