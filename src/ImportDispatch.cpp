/**
 * Author:    domin568
 * Created:   21.09.2025
 * Brief:     redirected API implementations
 **/

#include "../include/ImportDispatch.hpp"
#include "../include/COsxPpcEmu.hpp"
#include "../include/PpcStructures.hpp"

#include <array>
#include <climits>
#include <dirent.h>
#include <netdb.h>
#include <numeric>
#include <span>
#include <string_view>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <unistd.h>
#include <unordered_map>
#include <utime.h>
#include <vector>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <sys/xattr.h>
#endif

namespace import::callback
{
// Mac OS Memory Manager error codes
constexpr int noErr{ 0 };
constexpr int memFullErr{ -108 };
static thread_local int g_lastMemError{ noErr };

// ---------------------------------------------------------------------------
// FSRef ↔ host-path registry.
//
// CarbonLib's real implementation reaches the host filesystem through an HFS
// catalog (VolumeInfo / FSMount / catalog node IDs).  In the emulator we have
// no such catalog, so we keep a tiny side-table that maps the synthetic
// `cnid` we stored into FSRef.hidden[+8] back to the resolved POSIX path.
// FSPathMakeRef populates the table; FSGetCatalogInfo / FSRefMakePath /
// FSCompareFSRefs etc. consume it.
// ---------------------------------------------------------------------------
struct FSRefRecord
{
    std::string path;          // canonical POSIX path on the host
    std::uint32_t parentDirID; // synthetic parent CNID (parent inode)
    bool isDirectory;
};
static std::unordered_map<std::uint32_t, FSRefRecord> g_fsrefRegistry{};

inline void register_fsref( std::uint32_t cnid, std::string path, std::uint32_t parentDirID, bool isDir )
{
    g_fsrefRegistry[cnid] = FSRefRecord{ std::move( path ), parentDirID, isDir };
}

inline const FSRefRecord *lookup_fsref( std::uint32_t cnid )
{
    const auto it{ g_fsrefRegistry.find( cnid ) };
    return it == g_fsrefRegistry.end() ? nullptr : &it->second;
}

// Mac (HFS+) epoch is Jan 1, 1904 UTC; Unix epoch is Jan 1, 1970 UTC.
// Difference is 66 years including 17 leap days = 2,082,844,800 seconds.
constexpr std::uint64_t kMacEpochOffsetSeconds{ 2082844800ULL };

inline std::uint64_t unix_to_mac_seconds( std::int64_t unixSeconds )
{
    if (unixSeconds < -static_cast<std::int64_t>( kMacEpochOffsetSeconds ))
        return 0;
    return static_cast<std::uint64_t>( unixSeconds + static_cast<std::int64_t>( kMacEpochOffsetSeconds ) );
}

// OSErr PBGetCatInfoSync(CInfoPBPtr paramBlock)
// Gets catalog information about a file or directory synchronously
bool PBGetCatInfoSync( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [paramBlock] = *args;

    std::int32_t result{ -1 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write PBGetCatInfoSync return value" << std::endl;
        return false;
    }
    return true;
}

// OSErr FSpOpenRF(const FSSpec *spec, SInt8 permission, SInt16 *refNum)
// Opens the resource fork of a file
bool FSpOpenRF( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const void *, std::int8_t, std::int16_t *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [spec, permission, refNumPtr] = *args;

    std::uint32_t result{ 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write FSpOpenRF return value" << std::endl;
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Resource-fork ref-num registry, shared between FSpOpenResFile / FSpOpenRF /
// FSClose / CloseResFile.  Refnums issued to the guest are deliberately small
// positive SInt16 values starting at 100 so they don't collide with std streams.
// ---------------------------------------------------------------------------
static std::unordered_map<std::int16_t, int> g_resForkFds{};
static std::int16_t g_nextResRefNum{ 100 };
static std::int16_t g_currentResFile{ 0 }; // Resource Manager "current file"
static thread_local std::int16_t g_resError{ 0 };

// short FSpOpenResFile(const FSSpec *spec, SignedByte permission)
//
// Opens the resource fork of `spec` and returns a 16-bit reference number,
// or -1 on failure (with the global ResError set accordingly).  The classic
// Mac implementation walks the HFS catalog for `parID` + `name` to locate
// the file, then mmap's its resource map into the Resource Manager.  Here we
// re-use the FSRef registry that FSPathMakeRef / FSGetCatalogInfo populate:
// `spec.parID` is the parent inode (== an FSRef cnid we have already cached),
// so a single registry lookup gives us the parent's host path; the leaf is
// taken from the FSSpec's Str63 name field.
//
// FSSpec layout (BE):
//   +0 s16 vRefNum
//   +2 s32 parID
//   +6 u8  nameLen
//   +7 ... up to 63 bytes of leaf name
bool FSpOpenResFile( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const std::uint8_t *, std::int8_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [specPtr, permission] = *args;

    auto write_short_result{ [uc]( std::int32_t r ) -> bool {
        std::int32_t v{ r };
        if (uc_reg_write( uc, UC_PPC_REG_3, &v ) != UC_ERR_OK)
        {
            std::cerr << "Could not write FSpOpenResFile return value" << std::endl;
            return false;
        }
        return true;
    } };

    constexpr std::int16_t paramErr{ -50 };
    constexpr std::int16_t fnfErr{ -43 };
    constexpr std::int16_t opWrErr{ -49 };       // file already open with conflicting perms
    constexpr std::int16_t resFNotFound{ -193 }; // resource fork missing

    if (specPtr == nullptr)
    {
        g_resError = paramErr;
        return write_short_result( -1 );
    }

    // Parse the FSSpec
    auto readBE32{ []( const std::uint8_t *p ) -> std::uint32_t {
        return common::ensure_endianness( *reinterpret_cast<const std::uint32_t *>( p ), std::endian::big );
    } };
    const std::uint32_t parID{ readBE32( specPtr + 2 ) };
    const std::uint8_t nameLen{ specPtr[6] };
    const std::size_t copyLen{ std::min<std::size_t>( nameLen, 63 ) };
    const std::string leaf( reinterpret_cast<const char *>( specPtr + 7 ), copyLen );

    if (leaf.empty())
    {
        g_resError = fnfErr;
        return write_short_result( -1 );
    }

    // Resolve parent path via the FSRef registry
    const FSRefRecord *parent{ lookup_fsref( parID ) };
    if (parent == nullptr || parent->path.empty())
    {
        g_resError = fnfErr;
        return write_short_result( -1 );
    }

    std::string fullPath{ parent->path };
    if (fullPath.back() != '/')
        fullPath.push_back( '/' );
    fullPath += leaf;

    // Verify the data fork exists first (classic FSpOpenResFile fails fast on fnfErr)
    struct stat st{};
    if (::stat( fullPath.c_str(), &st ) != 0)
    {
        g_resError = fnfErr;
        return write_short_result( -1 );
    }

    // Open the macOS resource fork via the named-fork interface.
    // (`/..namedfork/rsrc` is the documented path for HFS+ resource forks.)
    const std::string rsrcPath{ fullPath + "_rsrc" }; // you need to extract resource forks for app to make it cross platform

    // Translate Mac File Manager permissions to POSIX open() flags.
    constexpr std::int8_t fsCurPerm{ 0 };
    constexpr std::int8_t fsRdPerm{ 1 };
    constexpr std::int8_t fsWrPerm{ 2 };
    constexpr std::int8_t fsRdWrPerm{ 3 };
    int oflags{ O_RDONLY };
    switch (permission)
    {
    case fsWrPerm:
        oflags = O_WRONLY;
        break;
    case fsRdWrPerm:
        oflags = O_RDWR;
        break;
    case fsCurPerm:
    case fsRdPerm:
    default:
        oflags = O_RDONLY;
        break;
    }

    const int fd{ ::open( rsrcPath.c_str(), oflags ) };
    if (fd < 0)
    {
        g_resError = ( errno == EACCES || errno == EPERM ) ? opWrErr : resFNotFound;
        return write_short_result( -1 );
    }

    // Allocate the next refnum, wrapping if necessary (avoid clashes with stdio).
    std::int16_t refNum{ g_nextResRefNum++ };
    if (g_nextResRefNum <= 0)
        g_nextResRefNum = 100;
    g_resForkFds[refNum] = fd;
    g_currentResFile = refNum; // classic Mac: opening a resource file makes it the current file
    g_resError = 0;

    return write_short_result( static_cast<std::int32_t>( refNum ) );
}

// ---------------------------------------------------------------------------
// Resource Manager state.
//
// Each entry in g_loadedResources tracks a Handle that we returned from
// Get1Resource (or any other resource-loading API).  CloseResFile uses this
// to release every handle owned by the closing file, except those the guest
// has explicitly DetachResource'd, which become orphans owned by the caller.
// ---------------------------------------------------------------------------
struct LoadedResource
{
    std::int16_t fileRefNum;
    std::uint32_t handleVa; // guest VA of the master pointer (Handle == Ptr*)
    std::uint32_t dataVa;   // guest VA of the resource bytes
    std::uint32_t size;
    std::uint32_t resType;
    std::int16_t resID;
    bool detached{ false };
};
static std::unordered_map<std::uint32_t, LoadedResource> g_loadedResources{};

// Classic Resource Manager error codes (see MacErrors.h)
constexpr std::int16_t kResNotFound{ -192 };
constexpr std::int16_t kResFNotFound{ -193 };
constexpr std::int16_t kMapReadErr{ -185 };
constexpr std::int16_t kEofErr{ -39 };
constexpr std::int16_t kRfNumErr{ -38 };

// Helper: parse the classic resource fork at `fd` and return guest-side
// allocations for the data of resource (type,id) on the *current* file.
// Returns 0 on failure with g_resError set.
static std::uint32_t load_one_resource( memory::CMemory *mem, int fd, std::uint32_t resType, std::int16_t resID,
                                        std::uint32_t &outDataVa, std::uint32_t &outSize )
{
    const auto rd16{ []( const std::uint8_t *p ) -> std::uint16_t {
        return static_cast<std::uint16_t>( ( p[0] << 8 ) | p[1] );
    } };
    const auto rd32{ []( const std::uint8_t *p ) -> std::uint32_t {
        return ( static_cast<std::uint32_t>( p[0] ) << 24 ) | ( static_cast<std::uint32_t>( p[1] ) << 16 ) |
               ( static_cast<std::uint32_t>( p[2] ) << 8 ) | static_cast<std::uint32_t>( p[3] );
    } };

    // 16-byte resource fork header
    std::uint8_t hdr[16]{};
    if (::pread( fd, hdr, sizeof( hdr ), 0 ) != static_cast<ssize_t>( sizeof( hdr ) ))
    {
        g_resError = kEofErr;
        return 0;
    }
    const std::uint32_t dataOff{ rd32( hdr + 0 ) };
    const std::uint32_t mapOff{ rd32( hdr + 4 ) };
    const std::uint32_t mapLen{ rd32( hdr + 12 ) };
    if (mapLen < 30)
    {
        g_resError = kMapReadErr;
        return 0;
    }

    std::vector<std::uint8_t> map( mapLen );
    if (::pread( fd, map.data(), mapLen, mapOff ) != static_cast<ssize_t>( mapLen ))
    {
        g_resError = kMapReadErr;
        return 0;
    }

    // Resource map header layout (28 bytes before the type list):
    //   +0  16 B  copy of resource fork header
    //   +16 u32   reserved (next handle)
    //   +20 u16   reserved (file ref)
    //   +22 u16   file attrs
    //   +24 u16   typeListOffset (relative to map start)
    //   +26 u16   nameListOffset
    const std::uint16_t typeListOffset{ rd16( map.data() + 24 ) };
    if (typeListOffset + 2u > mapLen)
    {
        g_resError = kMapReadErr;
        return 0;
    }

    const std::uint8_t *tl{ map.data() + typeListOffset };
    const std::int32_t numTypes{ static_cast<std::int32_t>( rd16( tl ) ) + 1 };

    const std::uint8_t *typeEntry{ tl + 2 };
    for (std::int32_t i = 0; i < numTypes; ++i, typeEntry += 8)
    {
        if (typeEntry + 8 > map.data() + mapLen)
            break;
        const std::uint32_t t{ rd32( typeEntry + 0 ) };
        const std::int32_t numRes{ static_cast<std::int32_t>( rd16( typeEntry + 4 ) ) + 1 };
        const std::uint16_t refOffFromTypeList{ rd16( typeEntry + 6 ) };
        if (t != resType)
            continue;

        const std::uint32_t refListOff{ static_cast<std::uint32_t>( typeListOffset ) + refOffFromTypeList };
        if (refListOff + static_cast<std::uint32_t>( numRes ) * 12u > mapLen)
        {
            g_resError = kMapReadErr;
            return 0;
        }

        const std::uint8_t *re{ map.data() + refListOff };
        for (std::int32_t j = 0; j < numRes; ++j, re += 12)
        {
            const std::int16_t id{ static_cast<std::int16_t>( rd16( re + 0 ) ) };
            // 24-bit big-endian dataOffset relative to dataOff
            const std::uint32_t off24{ ( static_cast<std::uint32_t>( re[5] ) << 16 ) |
                                       ( static_cast<std::uint32_t>( re[6] ) << 8 ) |
                                       static_cast<std::uint32_t>( re[7] ) };
            if (id != resID)
                continue;

            // Read u32 BE length, then the bytes
            std::uint8_t lenBuf[4]{};
            if (::pread( fd, lenBuf, 4, dataOff + off24 ) != 4)
            {
                g_resError = kEofErr;
                return 0;
            }
            const std::uint32_t bytes{ rd32( lenBuf ) };

            const std::uint32_t dataVa{ mem->heap_alloc( bytes == 0 ? 1u : bytes ) };
            if (dataVa == 0)
            {
                g_resError = -108; // memFullErr
                return 0;
            }
            if (bytes > 0)
            {
                void *hostBuf{ mem->get( dataVa ) };
                if (hostBuf == nullptr ||
                    ::pread( fd, hostBuf, bytes, dataOff + off24 + 4 ) != static_cast<ssize_t>( bytes ))
                {
                    g_resError = kEofErr;
                    return 0;
                }
            }

            // Allocate the master pointer (Handle = Ptr*).
            const std::uint32_t handleVa{ mem->heap_alloc( sizeof( std::uint32_t ) ) };
            if (handleVa == 0)
            {
                g_resError = -108;
                return 0;
            }
            auto *mp{ reinterpret_cast<std::uint32_t *>( mem->get( handleVa ) ) };
            *mp = common::ensure_endianness( dataVa, std::endian::big );

            outDataVa = dataVa;
            outSize = bytes;
            g_resError = 0;
            return handleVa;
        }
        // type matched but no such id
        g_resError = kResNotFound;
        return 0;
    }

    g_resError = kResNotFound;
    return 0;
}

// Handle Get1Resource(ResType theType, short theID)
// Loads resource (type,id) from the *current* resource file only (no chain
// search; that is GetResource's job).  Returns NULL on failure.
bool Get1Resource( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t, std::int16_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [resType, resID] = *args;

    auto write_handle{ [uc]( std::uint32_t h ) -> bool {
        std::uint32_t v{ h };
        if (uc_reg_write( uc, UC_PPC_REG_3, &v ) != UC_ERR_OK)
        {
            std::cerr << "Could not write Get1Resource return value" << std::endl;
            return false;
        }
        return true;
    } };

    if (g_currentResFile == 0)
    {
        g_resError = kResFNotFound;
        return write_handle( 0 );
    }
    const auto fdIt{ g_resForkFds.find( g_currentResFile ) };
    if (fdIt == g_resForkFds.end())
    {
        g_resError = kResFNotFound;
        return write_handle( 0 );
    }

    std::uint32_t dataVa{ 0 };
    std::uint32_t size{ 0 };
    const std::uint32_t handle{ load_one_resource( mem, fdIt->second, resType, resID, dataVa, size ) };
    if (handle == 0)
        return write_handle( 0 );

    g_loadedResources[handle] =
        LoadedResource{ g_currentResFile, handle, dataVa, size, resType, resID, false };

    return write_handle( handle );
}

// void DetachResource(Handle theResource)
// Disconnects `theResource` from the Resource Manager so the caller becomes
// responsible for disposing of the handle.  After this call, CloseResFile
// will not free the handle's storage.
bool DetachResource( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [handle] = *args;

    auto it{ g_loadedResources.find( handle ) };
    if (it == g_loadedResources.end())
    {
        g_resError = kResNotFound;
        return true; // void return
    }
    it->second.detached = true;
    g_loadedResources.erase( it );
    g_resError = 0;
    return true;
}

// void CloseResFile(short refNum)
// Closes the resource file identified by `refNum`, releases all resources
// that were loaded from it (except detached ones), and clears the current
// resource file if it was this one.
bool CloseResFile( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::int16_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [refNum] = *args;

    const auto fdIt{ g_resForkFds.find( refNum ) };
    if (fdIt == g_resForkFds.end())
    {
        g_resError = kRfNumErr;
        return true; // void return
    }
    ::close( fdIt->second );
    g_resForkFds.erase( fdIt );

    // Forget every still-attached resource owned by this file.
    for (auto it = g_loadedResources.begin(); it != g_loadedResources.end();)
    {
        if (it->second.fileRefNum == refNum && !it->second.detached)
            it = g_loadedResources.erase( it );
        else
            ++it;
    }

    if (g_currentResFile == refNum)
        g_currentResFile = 0;

    g_resError = 0;
    return true;
}

// ---------------------------------------------------------------------------
// FSp* Finder Info shims.
//
// Classic Finder info on HFS lived in a per-catalog-record blob.  On HFS+
// (and the macOS POSIX layer) it is stored in the extended attribute
// "com.apple.FinderInfo", a 32-byte buffer split as:
//   - bytes  0..15 : FInfo  (file)  / FolderInfo  (directory)
//   - bytes 16..31 : FXInfo (file)  / FolderXInfo (directory)
// FSpGetFInfo / FSpSetFInfo only touch the first 16 bytes.
// ---------------------------------------------------------------------------
//
// Resolve an FSSpec (BE: vRefNum/parID/Str63 name) to a host POSIX path by
// looking parID up in the FSRef registry that FSPathMakeRef populates.
static bool fsspec_to_host_path( const std::uint8_t *specPtr, std::string &out )
{
    if (specPtr == nullptr)
        return false;
    const std::uint32_t parID{ common::ensure_endianness(
        *reinterpret_cast<const std::uint32_t *>( specPtr + 2 ), std::endian::big ) };
    const std::uint8_t nameLen{ specPtr[6] };
    const std::size_t copy{ std::min<std::size_t>( nameLen, 63 ) };
    const std::string leaf( reinterpret_cast<const char *>( specPtr + 7 ), copy );
    if (leaf.empty())
        return false;

    const FSRefRecord *parent{ lookup_fsref( parID ) };
    if (parent == nullptr || parent->path.empty())
        return false;

    out = parent->path;
    if (out.back() != '/')
        out.push_back( '/' );
    out += leaf;
    return true;
}

// OSErr FSpGetFInfo(const FSSpec *spec, FInfo *fndrInfo)
//
// FInfo (16 bytes, BE):
//   +0  u32 fdType
//   +4  u32 fdCreator
//   +8  u16 fdFlags
//   +10 s16 fdLocation.v
//   +12 s16 fdLocation.h
//   +14 s16 fdFldr (reserved)
bool FSpGetFInfo( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const std::uint8_t *, std::uint8_t *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [specPtr, fndrInfoPtr] = *args;

    auto write_result{ [uc]( std::int32_t r ) -> bool {
        std::int32_t v{ r };
        if (uc_reg_write( uc, UC_PPC_REG_3, &v ) != UC_ERR_OK)
        {
            std::cerr << "Could not write FSpGetFInfo return value" << std::endl;
            return false;
        }
        return true;
    } };

    constexpr std::int32_t paramErr{ -50 };
    constexpr std::int32_t fnfErr{ -43 };

    if (specPtr == nullptr || fndrInfoPtr == nullptr)
        return write_result( paramErr );

    std::string hostPath;
    if (!fsspec_to_host_path( specPtr, hostPath ))
        return write_result( fnfErr );

    struct stat st{};
    if (::stat( hostPath.c_str(), &st ) != 0)
        return write_result( fnfErr );

    // Pull the 32-byte com.apple.FinderInfo xattr; absence is non-fatal (zeroed).
    std::uint8_t finderInfo[32]{};
#ifdef __APPLE__
    ::getxattr( hostPath.c_str(), "com.apple.FinderInfo", finderInfo, sizeof( finderInfo ), 0, XATTR_NOFOLLOW );
#endif

    // The xattr bytes are already stored in the on-disk Finder byte order
    // (big-endian, exactly what the guest expects), so just copy 16 bytes.
    std::memcpy( fndrInfoPtr, finderInfo, 16 );

    return write_result( 0 );
}

// OSErr FSpSetFInfo(const FSSpec *spec, const FInfo *fndrInfo)
bool FSpSetFInfo( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const std::uint8_t *, const std::uint8_t *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [specPtr, fndrInfoPtr] = *args;

    auto write_result{ [uc]( std::int32_t r ) -> bool {
        std::int32_t v{ r };
        if (uc_reg_write( uc, UC_PPC_REG_3, &v ) != UC_ERR_OK)
        {
            std::cerr << "Could not write FSpSetFInfo return value" << std::endl;
            return false;
        }
        return true;
    } };

    constexpr std::int32_t paramErr{ -50 };
    constexpr std::int32_t fnfErr{ -43 };
    constexpr std::int32_t wrPermErr{ -61 };
    constexpr std::int32_t ioErr{ -36 };

    if (specPtr == nullptr || fndrInfoPtr == nullptr)
        return write_result( paramErr );

    std::string hostPath;
    if (!fsspec_to_host_path( specPtr, hostPath ))
        return write_result( fnfErr );

    struct stat st{};
    if (::stat( hostPath.c_str(), &st ) != 0)
        return write_result( fnfErr );

    // Preserve the FXInfo half (bytes 16..31) by reading the existing xattr first.
    std::uint8_t finderInfo[32]{};
#ifdef __APPLE__
    ::getxattr( hostPath.c_str(), "com.apple.FinderInfo", finderInfo, sizeof( finderInfo ), 0, XATTR_NOFOLLOW );
#endif
    std::memcpy( finderInfo, fndrInfoPtr, 16 );

#ifdef __APPLE__
    if (::setxattr( hostPath.c_str(), "com.apple.FinderInfo", finderInfo, sizeof( finderInfo ), 0,
                    XATTR_NOFOLLOW ) != 0)
        return write_result( errno == EACCES || errno == EPERM ? wrPermErr : ioErr );
#endif

    return write_result( 0 );
}

// OSErr FSWrite(SInt16 refNum, SInt32 *count, const void *buffPtr)
// Writes data to an open file
bool FSWrite( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::int16_t, std::int32_t *, const void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [refNum, countPtr, buffPtr] = *args;

    std::uint32_t result{ 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write FSWrite return value" << std::endl;
        return false;
    }

    return true;
}

// OSErr FSClose(SInt16 refNum)
// Closes an open file. If `refNum` was issued by FSpOpenResFile / FSpOpenRF
// we forward the close() to the underlying host fd.
bool FSClose( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::int16_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [refNum] = *args;

    std::int32_t result{ 0 }; // noErr

    const auto it{ g_resForkFds.find( refNum ) };
    if (it != g_resForkFds.end())
    {
        if (::close( it->second ) != 0)
            result = -36; // ioErr
        g_resForkFds.erase( it );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write FSClose return value" << std::endl;
        return false;
    }

    return true;
}

// void BlockMoveData(const void *srcPtr, void *destPtr, Size byteCount)
// CoreServices.framework/Frameworks/CarbonCore.framework/Headers/MacMemory.h
bool BlockMoveData( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, void *, std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [srcPtr, destPtr, byteCount] = *args;

    if (byteCount > 0)
        ::memmove( destPtr, srcPtr, byteCount );

    return true;
}

// OSStatus FSPathMakeRef(const UInt8 *path, FSRef *ref, Boolean *isDirectory)
//
// CarbonLib internally calls FSPathMakeRefInternal -> PathGetObjectInfo -> CreateFSRef.
// CreateFSRef is the only routine that actually serializes bytes into the 80-byte FSRef.
// Reverse-engineered layout of FSRef.hidden[80] (all multi-byte fields are big-endian on
// the guest side):
//
//   +0   u16  volSig         (copied from VolumeInfo+0xA, opaque to clients)
//   +2   u16  encodingFlags  (low byte = TextEncoding hint;
//                              bit 14 / 0x4000 set when leaf is a regular file,
//                              bit 15 / 0x8000 set when the volume rejected the ref)
//   +4   u32  parentDirID    (HFS parent CNID)
//   +8   u32  cnid           (HFS leaf CNID -- file or directory)
//   +12  u32  reserved       (zero-initialised by the original memset(,,0x50))
//   +16  char name[64]       (UTF-8 leaf, NUL-terminated, max 63 chars before
//                              UTF8ToFSSpecName re-encodes it in place)
//
// For the emulator we have no real HFS catalog, so we synthesise plausible CNIDs from
// host inode numbers and stash the UTF-8 leaf name verbatim, which is more than enough
// for round-tripping through FSGetCatalogInfo / FSRefMakePath stubs.
bool FSPathMakeRef( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, void *, std::uint8_t *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, refPtr, isDirectoryPtr] = *args;

    // Carbon File Manager error codes
    constexpr std::int32_t noErr{ 0 };
    constexpr std::int32_t paramErr{ -50 };
    constexpr std::int32_t bdNamErr{ -37 };
    constexpr std::int32_t fnfErr{ -43 };

    auto write_result{ [uc]( std::int32_t status ) -> bool {
        std::int32_t r{ status };
        if (uc_reg_write( uc, UC_PPC_REG_3, &r ) != UC_ERR_OK)
        {
            std::cerr << "Could not write FSPathMakeRef return value" << std::endl;
            return false;
        }
        return true;
    } };

    if (path == nullptr || refPtr == nullptr)
        return write_result( paramErr );

    // PathGetObjectInfo bails out with -2110 for paths longer than 0x400 bytes.
    const std::size_t pathLen{ ::strnlen( path, 0x400 + 1 ) };
    if (pathLen == 0 || pathLen > 0x400)
        return write_result( bdNamErr );

    // Resolve to a canonical absolute path on the host (mirrors canonpath() in CarbonLib).
    char resolved[PATH_MAX]{};
    if (::realpath( path, resolved ) == nullptr)
        return write_result( fnfErr );

    struct stat st{};
    if (::lstat( resolved, &st ) != 0)
        return write_result( fnfErr );

    const bool isDir{ S_ISDIR( st.st_mode ) };

    // Derive a stand-in parentDirID from the parent directory's inode.
    std::uint32_t parentDirID{ 2 }; // HFS-style root CNID fallback
    {
        std::string parent{ resolved };
        const auto slash{ parent.find_last_of( '/' ) };
        if (slash == std::string::npos)
            parent = ".";
        else if (slash == 0)
            parent = "/";
        else
            parent.erase( slash );

        struct stat ps{};
        if (::stat( parent.c_str(), &ps ) == 0 && ps.st_ino != 0)
            parentDirID = static_cast<std::uint32_t>( ps.st_ino );
    }
    std::uint32_t cnid{ st.st_ino != 0 ? static_cast<std::uint32_t>( st.st_ino ) : 2u };

    // Extract the UTF-8 leaf name.
    std::string leaf;
    {
        const char *slash{ ::strrchr( resolved, '/' ) };
        if (slash == nullptr)
            leaf = resolved;
        else if (*( slash + 1 ) != '\0')
            leaf = slash + 1;
        else
            leaf = "/"; // volume root
    }
    if (leaf.size() > 63)
        return write_result( bdNamErr );

    // Build the 80-byte FSRef blob.
    //
    // encodingFlags: CreateFSRef stores `clrlwi r0, r30, 24` (low byte of TextEncoding)
    // OR'd with 0x4000 when the FSPathMakeRefInternal-supplied flag is 2 (regular file).
    constexpr std::uint16_t kVolumeSignatureHFS{ 0x4244 }; // 'BD' - opaque marker
    constexpr std::uint8_t kTextEncodingMacRoman{ 0 };
    std::uint16_t encodingFlags{ static_cast<std::uint16_t>( kTextEncodingMacRoman ) };
    if (!isDir)
        encodingFlags |= 0x4000;

    std::array<std::uint8_t, 80> fsref{};
    const auto put16{ [&]( std::size_t off, std::uint16_t v ) {
        v = common::ensure_endianness( v, std::endian::big );
        std::memcpy( fsref.data() + off, &v, sizeof( v ) );
    } };
    const auto put32{ [&]( std::size_t off, std::uint32_t v ) {
        v = common::ensure_endianness( v, std::endian::big );
        std::memcpy( fsref.data() + off, &v, sizeof( v ) );
    } };

    put16( 0, kVolumeSignatureHFS );
    put16( 2, encodingFlags );
    put32( 4, parentDirID );
    put32( 8, cnid );
    put32( 12, 0u ); // reserved / padding
    std::memcpy( fsref.data() + 16, leaf.data(), leaf.size() );
    // remainder of name[64] is already zero-initialised (NUL-terminated)

    std::memcpy( refPtr, fsref.data(), fsref.size() );

    // Cache the resolved host path so FSGetCatalogInfo / FSRefMakePath can recover it.
    register_fsref( cnid, std::string{ resolved }, parentDirID, isDir );

    if (isDirectoryPtr != nullptr)
        *isDirectoryPtr = isDir ? 1u : 0u;

    return write_result( noErr );
}

// OSStatus FSGetCatalogInfo(const FSRef *ref, FSCatalogInfoBitmap whichInfo,
//                           FSCatalogInfo *catalogInfo, HFSUniStr255 *outName,
//                           FSSpec *fsSpec, FSRef *parentRef)
//
// Reverse-engineered output layout (mac68k packing, all multi-byte fields BE):
//
//   FSCatalogInfo (144 bytes total)
//     +0   u16 nodeFlags
//     +2   s16 volume                (FSVolumeRefNum, we use 0)
//     +4   u32 parentDirID
//     +8   u32 nodeID                (cnid)
//     +12  u8  sharingFlags
//     +13  u8  userPrivileges
//     +14  u8  reserved1
//     +15  u8  reserved2
//     +16  UTCDateTime createDate            (8 = u16 highSec, u32 lowSec, u16 fraction)
//     +24  UTCDateTime contentModDate        (8)
//     +32  UTCDateTime attributeModDate      (8)
//     +40  UTCDateTime accessDate            (8)
//     +48  UTCDateTime backupDate            (8)
//     +56  u32 permissions[4]                (16 = FSPermissionInfo)
//     +72  u8  finderInfo[16]
//     +88  u8  extFinderInfo[16]
//     +104 u64 dataLogicalSize
//     +112 u64 dataPhysicalSize
//     +120 u64 rsrcLogicalSize
//     +128 u64 rsrcPhysicalSize
//     +136 u32 valence
//     +140 u32 textEncodingHint
//
//   HFSUniStr255 (514 bytes): u16 length + UniChar[255]
//   FSSpec       (70  bytes): s16 vRefNum + s32 parID + Str63 name
//   parentRef    (80  bytes FSRef of the leaf's parent directory)
bool FSGetCatalogInfo( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const std::uint8_t *, std::uint32_t, std::uint8_t *, std::uint8_t *, std::uint8_t *,
                                   std::uint8_t *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [refPtr, whichInfo, catInfoPtr, outNamePtr, fsSpecPtr, parentRefPtr] = *args;

    constexpr std::int32_t noErr{ 0 };
    constexpr std::int32_t paramErr{ -50 };
    constexpr std::int32_t fnfErr{ -43 };
    constexpr std::int32_t nsvErr{ -35 };

    auto write_result{ [uc]( std::int32_t status ) -> bool {
        std::int32_t r{ status };
        if (uc_reg_write( uc, UC_PPC_REG_3, &r ) != UC_ERR_OK)
        {
            std::cerr << "Could not write FSGetCatalogInfo return value" << std::endl;
            return false;
        }
        return true;
    } };

    if (refPtr == nullptr)
        return write_result( paramErr );

    // ----- 1. Parse the input FSRef (BE on the guest) -----
    auto readBE16{ []( const std::uint8_t *p ) -> std::uint16_t {
        return common::ensure_endianness( *reinterpret_cast<const std::uint16_t *>( p ), std::endian::big );
    } };
    auto readBE32{ []( const std::uint8_t *p ) -> std::uint32_t {
        return common::ensure_endianness( *reinterpret_cast<const std::uint32_t *>( p ), std::endian::big );
    } };

    const std::uint16_t volSig{ readBE16( refPtr + 0 ) };
    const std::uint16_t encFlags{ readBE16( refPtr + 2 ) };
    const std::uint32_t parentDirID{ readBE32( refPtr + 4 ) };
    const std::uint32_t cnid{ readBE32( refPtr + 8 ) };
    const char *embeddedName{ reinterpret_cast<const char *>( refPtr + 16 ) };

    // ----- 2. Recover host path / metadata -----
    const FSRefRecord *rec{ lookup_fsref( cnid ) };
    std::string hostPath{};
    std::string leafName{};
    bool isDir{ ( encFlags & 0x4000 ) == 0 }; // CreateFSRef sets 0x4000 only for files

    if (rec != nullptr)
    {
        hostPath = rec->path;
        isDir = rec->isDirectory;
    }
    // Fall back to the leaf name embedded in the FSRef
    {
        const std::size_t maxLen{ ::strnlen( embeddedName, 64 ) };
        leafName.assign( embeddedName, embeddedName + maxLen );
    }

    struct stat st{};
    bool haveStat{ false };
    if (!hostPath.empty() && ::lstat( hostPath.c_str(), &st ) == 0)
    {
        haveStat = true;
        if (leafName.empty())
        {
            const auto slash{ hostPath.find_last_of( '/' ) };
            leafName = ( slash == std::string::npos ) ? hostPath : hostPath.substr( slash + 1 );
            if (leafName.empty())
                leafName = "/";
        }
    }
    else if (!hostPath.empty())
    {
        return write_result( fnfErr ); // path was registered but no longer reachable
    }
    if (volSig == 0 && rec == nullptr)
    {
        // ref was never produced by FSPathMakeRef; nothing we can do
        return write_result( nsvErr );
    }

    // ----- 3. Build FSCatalogInfo -----
    if (catInfoPtr != nullptr && whichInfo != 0)
    {
        std::array<std::uint8_t, 144> ci{};
        const auto put16{ [&]( std::size_t off, std::uint16_t v ) {
            v = common::ensure_endianness( v, std::endian::big );
            std::memcpy( ci.data() + off, &v, sizeof( v ) );
        } };
        const auto put32{ [&]( std::size_t off, std::uint32_t v ) {
            v = common::ensure_endianness( v, std::endian::big );
            std::memcpy( ci.data() + off, &v, sizeof( v ) );
        } };
        const auto put64{ [&]( std::size_t off, std::uint64_t v ) {
            v = common::ensure_endianness( v, std::endian::big );
            std::memcpy( ci.data() + off, &v, sizeof( v ) );
        } };
        const auto putUTC{ [&]( std::size_t off, std::int64_t unixSec ) {
            const std::uint64_t mac{ unix_to_mac_seconds( unixSec ) };
            // UTCDateTime: u16 highSeconds, u32 lowSeconds, u16 fraction (mac68k packed = 8B)
            put16( off + 0, static_cast<std::uint16_t>( ( mac >> 32 ) & 0xFFFF ) );
            put32( off + 2, static_cast<std::uint32_t>( mac & 0xFFFFFFFF ) );
            put16( off + 6, 0 );
        } };

        // kFSCatInfoNodeFlags
        if (whichInfo & 0x00000002)
        {
            std::uint16_t nodeFlags{ 0 };
            if (isDir)
                nodeFlags |= 0x0010; // kFSNodeIsDirectoryMask
            if (haveStat && ( st.st_mode & 0222 ) == 0)
                nodeFlags |= 0x0001; // kFSNodeLockedMask
            put16( 0, nodeFlags );
        }
        // kFSCatInfoVolume
        if (whichInfo & 0x00000004)
            put16( 2, 0 ); // synthetic single-volume emulator
        // kFSCatInfoParentDirID
        if (whichInfo & 0x00000008)
            put32( 4, parentDirID );
        // kFSCatInfoNodeID
        if (whichInfo & 0x00000010)
            put32( 8, cnid );
        // sharingFlags / userPrivs / reserved1/2 left zero

        // Dates
        if (haveStat)
        {
#ifdef __APPLE__
            const std::int64_t cTime{ st.st_birthtimespec.tv_sec };
#else
            const std::int64_t cTime{ st.st_ctime };
#endif
            if (whichInfo & 0x00000020) // kFSCatInfoCreateDate
                putUTC( 16, cTime );
            if (whichInfo & 0x00000040) // kFSCatInfoContentMod
                putUTC( 24, st.st_mtime );
            if (whichInfo & 0x00000080) // kFSCatInfoAttrMod
                putUTC( 32, st.st_ctime );
            if (whichInfo & 0x00000100) // kFSCatInfoAccessDate
                putUTC( 40, st.st_atime );
            if (whichInfo & 0x00000200) // kFSCatInfoBackupDate
                putUTC( 48, 0 );
        }

        // kFSCatInfoPermissions (FSPermissionInfo: userID, groupID, reserved1, userAccess, mode, fileSec)
        if (( whichInfo & 0x00000400 ) && haveStat)
        {
            put32( 56, static_cast<std::uint32_t>( st.st_uid ) );
            put32( 60, static_cast<std::uint32_t>( st.st_gid ) );
            ci[64] = 0;                                                     // reserved1
            ci[65] = 0;                                                     // userAccess
            put16( 66, static_cast<std::uint16_t>( st.st_mode & 0xFFFF ) ); // mode
            put32( 68, 0 );                                                 // fileSec (FSFileSecurityRef)
        }

        // FinderInfo / ExtFinderInfo - leave zero (16 bytes each).
        // We could synthesise a type/creator from the file extension here, but
        // most callers just look at the flags which are zero by default.

        // Sizes (files only)
        if (haveStat && !isDir)
        {
            const std::uint64_t logSize{ static_cast<std::uint64_t>( st.st_size ) };
            const std::uint64_t physSize{ static_cast<std::uint64_t>( st.st_blocks ) * 512u };
            if (whichInfo & 0x00004000) // kFSCatInfoDataSizes
            {
                put64( 104, logSize );
                put64( 112, physSize );
            }
            if (whichInfo & 0x00008000) // kFSCatInfoRsrcSizes
            {
                // Try the AppleDouble sidecar / ._foo resource fork on macOS via xattr length
                std::uint64_t rsrcSize{ 0 };
#ifdef __APPLE__
                if (!hostPath.empty())
                {
                    const ssize_t rs{
                        ::getxattr( hostPath.c_str(), "com.apple.ResourceFork", nullptr, 0, 0, XATTR_NOFOLLOW ) };
                    if (rs > 0)
                        rsrcSize = static_cast<std::uint64_t>( rs );
                }
#endif
                put64( 120, rsrcSize );
                put64( 128, rsrcSize );
            }
        }

        // kFSCatInfoValence (folders only)
        if (( whichInfo & 0x00002000 ) && isDir && !hostPath.empty())
        {
            std::uint32_t valence{ 0 };
            if (DIR *d = ::opendir( hostPath.c_str() ))
            {
                while (::readdir( d ))
                    ++valence;
                ::closedir( d );
                if (valence >= 2)
                    valence -= 2; // drop "." and ".."
            }
            put32( 136, valence );
        }

        // kFSCatInfoTextEncoding
        if (whichInfo & 0x00000001)
            put32( 140, static_cast<std::uint32_t>( encFlags & 0x00FF ) );

        std::memcpy( catInfoPtr, ci.data(), ci.size() );
    }

    // ----- 4. outName (HFSUniStr255) — UTF-8 leaf converted to UTF-16BE -----
    if (outNamePtr != nullptr)
    {
        std::array<std::uint8_t, 514> uni{};
        std::uint16_t len{ 0 };
        for (char c : leafName)
        {
            if (len >= 255)
                break;
            // Naive UTF-8 → UTF-16: only ASCII produces a clean code unit; any
            // non-ASCII byte is passed through with its high bit set, which is
            // sufficient for the test workloads we care about.
            const std::uint16_t u{ static_cast<std::uint16_t>( static_cast<std::uint8_t>( c ) ) };
            const std::uint16_t be{ common::ensure_endianness( u, std::endian::big ) };
            std::memcpy( uni.data() + 2 + len * 2, &be, 2 );
            ++len;
        }
        const std::uint16_t lenBE{ common::ensure_endianness( len, std::endian::big ) };
        std::memcpy( uni.data(), &lenBE, 2 );
        std::memcpy( outNamePtr, uni.data(), uni.size() );
    }

    // ----- 5. FSSpec (legacy) -----
    if (fsSpecPtr != nullptr)
    {
        std::array<std::uint8_t, 70> spec{};
        // vRefNum (s16 BE) = 0
        // parID    (s32 BE) = parentDirID
        const std::uint32_t parIDbe{ common::ensure_endianness( parentDirID, std::endian::big ) };
        std::memcpy( spec.data() + 2, &parIDbe, 4 );
        // Str63 Pascal name: byte length + bytes
        const std::size_t nameLen{ std::min<std::size_t>( leafName.size(), 63 ) };
        spec[6] = static_cast<std::uint8_t>( nameLen );
        std::memcpy( spec.data() + 7, leafName.data(), nameLen );
        std::memcpy( fsSpecPtr, spec.data(), spec.size() );
    }

    // ----- 6. parentRef — synthesise an FSRef for the parent directory -----
    if (parentRefPtr != nullptr)
    {
        std::array<std::uint8_t, 80> pref{};
        const auto put16{ [&]( std::size_t off, std::uint16_t v ) {
            v = common::ensure_endianness( v, std::endian::big );
            std::memcpy( pref.data() + off, &v, 2 );
        } };
        const auto put32{ [&]( std::size_t off, std::uint32_t v ) {
            v = common::ensure_endianness( v, std::endian::big );
            std::memcpy( pref.data() + off, &v, 4 );
        } };

        // Walk one level up
        std::string parentPath;
        std::string parentLeaf;
        std::uint32_t grandParentID{ 2 };
        if (!hostPath.empty())
        {
            parentPath = hostPath;
            const auto slash{ parentPath.find_last_of( '/' ) };
            if (slash == 0)
                parentPath = "/";
            else if (slash != std::string::npos)
                parentPath.erase( slash );
            const auto slash2{ parentPath.find_last_of( '/' ) };
            parentLeaf = ( slash2 == std::string::npos ) ? parentPath : parentPath.substr( slash2 + 1 );
            if (parentLeaf.empty())
                parentLeaf = "/";
            struct stat ps{};
            if (::stat( parentPath.c_str(), &ps ) == 0)
            {
                std::string gp{ parentPath };
                const auto gpslash{ gp.find_last_of( '/' ) };
                if (gpslash == 0)
                    gp = "/";
                else if (gpslash != std::string::npos)
                    gp.erase( gpslash );
                struct stat gps{};
                if (::stat( gp.c_str(), &gps ) == 0 && gps.st_ino != 0)
                    grandParentID = static_cast<std::uint32_t>( gps.st_ino );
                // Cache so the caller can FSGetCatalogInfo on parentRef too.
                register_fsref( parentDirID, std::move( parentPath ), grandParentID, true );
            }
        }

        put16( 0, volSig );
        put16( 2, 0 );             // parent is a directory → no 0x4000 bit
        put32( 4, grandParentID ); // parent's parent
        put32( 8, parentDirID );   // parent's own cnid
        put32( 12, 0 );
        const std::size_t copy{ std::min<std::size_t>( parentLeaf.size(), 63 ) };
        std::memcpy( pref.data() + 16, parentLeaf.data(), copy );
        std::memcpy( parentRefPtr, pref.data(), pref.size() );
    }

    return write_result( noErr );
}
// Handle TempNewHandle(Size logicalSize, OSErr* resultCode)
// Allocate a relocatable memory block of a specified size.
bool TempNewHandle( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [logicalSize] = *args;

    const std::uint32_t alloc{ mem->heap_alloc( logicalSize ) };
    std::uint32_t *ptrHost{
        reinterpret_cast<std::uint32_t *>( mem->to_host( mem->heap_alloc( sizeof( std::uint32_t ) ) ) ) };
    *ptrHost = common::ensure_endianness( alloc, std::endian::big );
    std::uint32_t ptrGuest{ mem->to_guest( ptrHost ) };

    g_lastMemError = ( alloc == 0 ) ? memFullErr : noErr;

    if (uc_reg_write( uc, UC_PPC_REG_3, &ptrGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write TempNewHandle return value" << std::endl;
        return false;
    }
    return true;
}

// Size GetHandleSize(Handle h)
// Returns the size of the allocated memory block referenced by a handle.
bool GetHandleSize( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [handleGuest] = *args;

    std::uint32_t size{ 0 };
    if (handleGuest != 0)
    {
        const std::uint32_t *handleHost{ reinterpret_cast<const std::uint32_t *>( mem->get( handleGuest ) ) };
        if (handleHost != nullptr)
        {
            const std::uint32_t ptrGuest{ common::ensure_endianness( *handleHost, std::endian::big ) };
            size = static_cast<std::uint32_t>( mem->get_alloc_size( ptrGuest ) );
        }
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &size ) != UC_ERR_OK)
    {
        std::cerr << "Could not write GetHandleSize return value" << std::endl;
        return false;
    }
    return true;
}

// void DisposeHandle(Handle h)
// Releases the memory occupied by a relocatable block.
bool DisposeHandle( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [handleGuest] = *args;

    // Simply set error status - no actual freeing happens
    if (handleGuest == 0)
    {
        g_lastMemError = memFullErr;
    }
    else
    {
        g_lastMemError = noErr;
    }
    return true;
}

// OSErr HandAndHand(Handle hand1, Handle hand2)
// Concatenates the contents of one relocatable block to the end of another.
// The Memory Manager expands hand2's size and appends hand1's data to it.
bool HandAndHand( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t, std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [hand1Guest, hand2Guest] = *args;

    std::uint32_t result{ noErr };

    if (hand1Guest == 0 || hand2Guest == 0)
    {
        result = memFullErr;
        g_lastMemError = memFullErr;
    }
    else
    {
        std::uint32_t *handle1Host{ reinterpret_cast<std::uint32_t *>( mem->get( hand1Guest ) ) };
        std::uint32_t *handle2Host{ reinterpret_cast<std::uint32_t *>( mem->get( hand2Guest ) ) };

        if (handle1Host == nullptr || handle2Host == nullptr)
        {
            result = memFullErr;
            g_lastMemError = memFullErr;
        }
        else
        {
            const std::uint32_t ptr1Guest{ common::ensure_endianness( *handle1Host, std::endian::big ) };
            const std::uint32_t ptr2Guest{ common::ensure_endianness( *handle2Host, std::endian::big ) };

            const std::size_t size1{ mem->get_alloc_size( ptr1Guest ) };
            const std::size_t size2{ mem->get_alloc_size( ptr2Guest ) };

            const std::size_t newSize{ size2 + size1 };

            const std::uint32_t newAlloc{ mem->heap_alloc( newSize ) };
            if (newAlloc == 0)
            {
                result = memFullErr;
                g_lastMemError = memFullErr;
            }
            else
            {
                void *ptr1{ mem->get( ptr1Guest ) };
                void *ptr2{ mem->get( ptr2Guest ) };
                void *newPtr{ mem->get( newAlloc ) };

                if (ptr2 && newPtr)
                {
                    ::memcpy( newPtr, ptr2, size2 );
                    if (ptr1)
                    {
                        ::memcpy( static_cast<char *>( newPtr ) + size2, ptr1, size1 );
                    }
                }
                *handle2Host = common::ensure_endianness( newAlloc, std::endian::big );
                result = noErr;
                g_lastMemError = noErr;
            }
        }
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write HandAndHand return value" << std::endl;
        return false;
    }
    return true;
}

// void HLock(Handle h)
// Locks a relocatable block so it cannot be moved during heap compaction.
bool HLock( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [handleGuest] = *args;

    if (handleGuest == 0)
    {
        g_lastMemError = memFullErr;
    }
    else
    {
        g_lastMemError = noErr;
    }
    return true;
}

// void HLockHi(Handle h)
// Locks a relocatable block at the top of the heap so it cannot be moved.
bool HLockHi( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [handleGuest] = *args;
    if (handleGuest == 0)
    {
        g_lastMemError = memFullErr;
    }
    else
    {
        g_lastMemError = noErr;
    }

    return true;
}

// void HUnlock(Handle h)
// Unlocks a relocatable block so it can be moved during heap compaction.
bool HUnlock( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [handleGuest] = *args;

    if (handleGuest == 0)
    {
        g_lastMemError = memFullErr;
    }
    else
    {
        g_lastMemError = noErr;
    }
    return true;
}

// OSErr MemError(void)
// Returns the error code from the last Memory Manager operation.
bool MemError( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    std::uint32_t err{ static_cast<std::uint32_t>( g_lastMemError ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &err ) != UC_ERR_OK)
    {
        std::cerr << "Could not write MemError return value" << std::endl;
        return false;
    }
    return true;
}

// Handle NewHandle(Size logicalSize)
// Allocate a relocatable memory block of a specified size.
bool NewHandle( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [logicalSize] = *args;

    const std::uint32_t alloc{ mem->heap_alloc( logicalSize ) };
    std::uint32_t *ptrHost{
        reinterpret_cast<std::uint32_t *>( mem->to_host( mem->heap_alloc( sizeof( std::uint32_t ) ) ) ) };
    *ptrHost = common::ensure_endianness( alloc, std::endian::big );
    std::uint32_t ptrGuest{ mem->to_guest( ptrHost ) };

    // Set memory error status
    g_lastMemError = ( alloc == 0 ) ? memFullErr : noErr;

    if (uc_reg_write( uc, UC_PPC_REG_3, &ptrGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write NewHandle return value" << std::endl;
        return false;
    }

    return true;
}

// Handle NewHandleClear(Size logicalSize)
// Allocate a relocatable memory block and clear it to zeros.
bool NewHandleClear( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [logicalSize] = *args;

    const std::uint32_t alloc{ mem->heap_alloc( logicalSize ) };

    // Clear the allocated memory
    void *allocPtr{ mem->get( alloc ) };
    if (allocPtr)
    {
        ::memset( allocPtr, 0, logicalSize );
    }

    std::uint32_t *ptrHost{
        reinterpret_cast<std::uint32_t *>( mem->to_host( mem->heap_alloc( sizeof( std::uint32_t ) ) ) ) };
    *ptrHost = common::ensure_endianness( alloc, std::endian::big );
    std::uint32_t ptrGuest{ mem->to_guest( ptrHost ) };

    // Set memory error status
    g_lastMemError = ( alloc == 0 ) ? memFullErr : noErr;

    if (uc_reg_write( uc, UC_PPC_REG_3, &ptrGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write NewHandleClear return value" << std::endl;
        return false;
    }

    return true;
}

// OSErr PtrAndHand(const void *ptr1, Handle hand2, long size)
// Concatenates part or all of a memory block to the end of a relocatable block.
bool PtrAndHand( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const void *, std::uint32_t, std::int32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [ptr1, hand2Guest, size] = *args;

    std::int32_t result{ noErr };

    // Validate parameters
    if (ptr1 == nullptr || hand2Guest == 0 || size < 0)
    {
        result = memFullErr;
        g_lastMemError = memFullErr;
    }
    else
    {
        // Handle is a pointer to a pointer - get the handle's host address
        std::uint32_t *handleHost{ reinterpret_cast<std::uint32_t *>( mem->get( hand2Guest ) ) };
        if (handleHost == nullptr)
        {
            result = memFullErr;
            g_lastMemError = memFullErr;
        }
        else
        {
            // Read the pointer value (big-endian) that the handle points to
            const std::uint32_t oldPtrGuest{ common::ensure_endianness( *handleHost, std::endian::big ) };
            const std::size_t oldSize{ mem->get_alloc_size( oldPtrGuest ) };

            // Calculate new size
            const std::size_t newSize{ oldSize + static_cast<std::size_t>( size ) };

            // Allocate new memory block
            const std::uint32_t newAlloc{ mem->heap_alloc( newSize ) };

            if (newAlloc == 0)
            {
                result = memFullErr;
                g_lastMemError = memFullErr;
            }
            else
            {
                // Copy old data to new location
                void *oldPtr{ mem->get( oldPtrGuest ) };
                void *newPtr{ mem->get( newAlloc ) };
                if (oldPtr && newPtr)
                {
                    ::memcpy( newPtr, oldPtr, oldSize );

                    // Concatenate new data from ptr1 to the end
                    ::memcpy( static_cast<char *>( newPtr ) + oldSize, ptr1, size );
                }

                // Update the handle to point to the new allocation
                *handleHost = common::ensure_endianness( newAlloc, std::endian::big );
                result = noErr;
                g_lastMemError = noErr;
            }
        }
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write PtrAndHand return value" << std::endl;
        return false;
    }
    return true;
}

// void SetHandleSize(Handle h, Size newSize)
// Changes the logical size of the relocatable block associated with a handle.
bool SetHandleSize( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t, std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [handleGuest, newSize] = *args;

    if (handleGuest == 0)
    {
        g_lastMemError = memFullErr;
        return true;
    }

    // Handle is a pointer to a pointer - get the handle's host address
    std::uint32_t *handleHost{ reinterpret_cast<std::uint32_t *>( mem->get( handleGuest ) ) };
    if (handleHost == nullptr)
    {
        g_lastMemError = memFullErr;
        return true;
    }

    // Read the pointer value (big-endian) that the handle points to
    const std::uint32_t oldPtrGuest{ common::ensure_endianness( *handleHost, std::endian::big ) };
    const std::size_t oldSize{ mem->get_alloc_size( oldPtrGuest ) };

    if (newSize <= oldSize)
    {
        // Shrinking or same size - just update the tracked size
        mem->set_alloc_size( oldPtrGuest, newSize );
        g_lastMemError = noErr;
    }
    else
    {
        // Growing - need to allocate new memory and copy old data
        const std::uint32_t newAlloc{ mem->heap_alloc( newSize ) };

        if (newAlloc == 0)
        {
            g_lastMemError = memFullErr;
        }
        else
        {
            // Copy old data to new location
            void *oldPtr{ mem->get( oldPtrGuest ) };
            void *newPtr{ mem->get( newAlloc ) };
            if (oldPtr && newPtr)
            {
                ::memcpy( newPtr, oldPtr, oldSize );
            }

            // Update the handle to point to the new allocation
            *handleHost = common::ensure_endianness( newAlloc, std::endian::big );
            g_lastMemError = noErr;
        }
    }

    return true;
}

// int *___error(void);
// Returns a pointer to the errno variable
bool ___error( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    // Get the address of the _errno import entry
    std::optional<uint32_t> errnoVa{ common::get_import_entry_va_by_name( "_errno" ) };
    if (!errnoVa.has_value())
    {
        std::cerr << "Could not find _errno symbol" << std::endl;
        return false;
    }

    // Return pointer to the errno location in r3
    uint32_t errnoAddr = *errnoVa;
    if (uc_reg_write( uc, UC_PPC_REG_3, &errnoAddr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write ___error return value" << std::endl;
        return false;
    }
    return true;
}

// int ___isctype(int c, unsigned long mask);
// Check if character has certain properties based on bitmask (same as ___istype)
// This is an alias for ___istype on macOS
bool ___isctype( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [c, mask] = *args;

    uint32_t chartype = 0;

    if (c >= 'A' && c <= 'Z')
        chartype |= _CTYPE_U | _CTYPE_X;
    if (c >= 'a' && c <= 'z')
        chartype |= _CTYPE_L | _CTYPE_X;
    if (c >= '0' && c <= '9')
        chartype |= _CTYPE_D | _CTYPE_X;
    if (c >= 'A' && c <= 'F')
        chartype |= _CTYPE_X;
    if (c >= 'a' && c <= 'f')
        chartype |= _CTYPE_X;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v')
        chartype |= _CTYPE_S;
    if (c == ' ' || c == '\t')
        chartype |= _CTYPE_B;
    if (( c >= 0 && c <= 31 ) || c == 127)
        chartype |= _CTYPE_C;
    if (( c >= 33 && c <= 47 ) || ( c >= 58 && c <= 64 ) || ( c >= 91 && c <= 96 ) || ( c >= 123 && c <= 126 ))
        chartype |= _CTYPE_P;

    // Check if any of the requested mask bits are set
    uint32_t result = ( chartype & mask ) != 0 ? 1 : 0;

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write ___isctype return value" << std::endl;
        return false;
    }
    return true;
}

// int __istype(int c, unsigned long mask);
// Check if character has certain properties based on bitmask
bool ___istype( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [c, mask] = *args;

    uint32_t chartype = 0;

    if (c >= 'A' && c <= 'Z')
        chartype |= _CTYPE_U | _CTYPE_X;
    if (c >= 'a' && c <= 'z')
        chartype |= _CTYPE_L | _CTYPE_X;
    if (c >= '0' && c <= '9')
        chartype |= _CTYPE_D | _CTYPE_X;
    if (c >= 'A' && c <= 'F')
        chartype |= _CTYPE_X;
    if (c >= 'a' && c <= 'f')
        chartype |= _CTYPE_X;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v')
        chartype |= _CTYPE_S;
    if (c == ' ' || c == '\t')
        chartype |= _CTYPE_B;
    if (( c >= 0 && c <= 31 ) || c == 127)
        chartype |= _CTYPE_C;
    if (( c >= 33 && c <= 47 ) || ( c >= 58 && c <= 64 ) || ( c >= 91 && c <= 96 ) || ( c >= 123 && c <= 126 ))
        chartype |= _CTYPE_P;

    // Check if any of the requested mask bits are set
    uint32_t result = ( chartype & mask ) != 0 ? 1 : 0;

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write ___istype return value" << std::endl;
        return false;
    }
    return true;
}

// int ___tolower(int c);
// Converts uppercase letter to lowercase
bool ___tolower( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [c] = *args;

    // Convert to lowercase if uppercase letter
    uint32_t result = ( c >= 'A' && c <= 'Z' ) ? ( c + 32 ) : c;

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write ___tolower return value" << std::endl;
        return false;
    }
    return true;
}

// int ___toupper(int c);
// Converts lowercase letter to uppercase
bool ___toupper( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [c] = *args;

    // Convert to uppercase if lowercase letter
    uint32_t result = ( c >= 'a' && c <= 'z' ) ? ( c - 32 ) : c;

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write ___toupper return value" << std::endl;
        return false;
    }
    return true;
}

// int _setjmp(jmp_buf env);
// Save calling environment for later use by longjmp
bool _setjmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [envPtr] = *args;

    if (!envPtr)
    {
        std::cerr << "_setjmp: null jmp_buf pointer" << std::endl;
        return false;
    }

    auto *jmpBuf = static_cast<guest::jmp_buf *>( envPtr );

    // Save registers to jmp_buf
    uint32_t r1, r2, r13, r14, r15, r16, r17, r18, r19, r20, r21;
    uint32_t r22, r23, r24, r25, r26, r27, r28, r29, r30, r31;
    uint32_t cr, lr, ctr, xer;

    uc_reg_read( uc, UC_PPC_REG_1, &r1 );
    uc_reg_read( uc, UC_PPC_REG_2, &r2 );
    uc_reg_read( uc, UC_PPC_REG_13, &r13 );
    uc_reg_read( uc, UC_PPC_REG_14, &r14 );
    uc_reg_read( uc, UC_PPC_REG_15, &r15 );
    uc_reg_read( uc, UC_PPC_REG_16, &r16 );
    uc_reg_read( uc, UC_PPC_REG_17, &r17 );
    uc_reg_read( uc, UC_PPC_REG_18, &r18 );
    uc_reg_read( uc, UC_PPC_REG_19, &r19 );
    uc_reg_read( uc, UC_PPC_REG_20, &r20 );
    uc_reg_read( uc, UC_PPC_REG_21, &r21 );
    uc_reg_read( uc, UC_PPC_REG_22, &r22 );
    uc_reg_read( uc, UC_PPC_REG_23, &r23 );
    uc_reg_read( uc, UC_PPC_REG_24, &r24 );
    uc_reg_read( uc, UC_PPC_REG_25, &r25 );
    uc_reg_read( uc, UC_PPC_REG_26, &r26 );
    uc_reg_read( uc, UC_PPC_REG_27, &r27 );
    uc_reg_read( uc, UC_PPC_REG_28, &r28 );
    uc_reg_read( uc, UC_PPC_REG_29, &r29 );
    uc_reg_read( uc, UC_PPC_REG_30, &r30 );
    uc_reg_read( uc, UC_PPC_REG_31, &r31 );
    uc_reg_read( uc, UC_PPC_REG_CR, &cr );
    uc_reg_read( uc, UC_PPC_REG_LR, &lr );
    uc_reg_read( uc, UC_PPC_REG_CTR, &ctr );
    uc_reg_read( uc, UC_PPC_REG_XER, &xer );

    // Store in big-endian format
    jmpBuf->r1 = common::ensure_endianness( r1, std::endian::big );
    jmpBuf->r2 = common::ensure_endianness( r2, std::endian::big );
    jmpBuf->r13 = common::ensure_endianness( r13, std::endian::big );
    jmpBuf->r14 = common::ensure_endianness( r14, std::endian::big );
    jmpBuf->r15 = common::ensure_endianness( r15, std::endian::big );
    jmpBuf->r16 = common::ensure_endianness( r16, std::endian::big );
    jmpBuf->r17 = common::ensure_endianness( r17, std::endian::big );
    jmpBuf->r18 = common::ensure_endianness( r18, std::endian::big );
    jmpBuf->r19 = common::ensure_endianness( r19, std::endian::big );
    jmpBuf->r20 = common::ensure_endianness( r20, std::endian::big );
    jmpBuf->r21 = common::ensure_endianness( r21, std::endian::big );
    jmpBuf->r22 = common::ensure_endianness( r22, std::endian::big );
    jmpBuf->r23 = common::ensure_endianness( r23, std::endian::big );
    jmpBuf->r24 = common::ensure_endianness( r24, std::endian::big );
    jmpBuf->r25 = common::ensure_endianness( r25, std::endian::big );
    jmpBuf->r26 = common::ensure_endianness( r26, std::endian::big );
    jmpBuf->r27 = common::ensure_endianness( r27, std::endian::big );
    jmpBuf->r28 = common::ensure_endianness( r28, std::endian::big );
    jmpBuf->r29 = common::ensure_endianness( r29, std::endian::big );
    jmpBuf->r30 = common::ensure_endianness( r30, std::endian::big );
    jmpBuf->r31 = common::ensure_endianness( r31, std::endian::big );
    jmpBuf->cr = common::ensure_endianness( cr, std::endian::big );
    jmpBuf->lr = common::ensure_endianness( lr, std::endian::big );
    jmpBuf->ctr = common::ensure_endianness( ctr, std::endian::big );
    jmpBuf->xer = common::ensure_endianness( xer, std::endian::big );

    // Return 0 for setjmp
    uint32_t ret = 0;
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write _setjmp return value" << std::endl;
        return false;
    }

    return true;
}

// void _longjmp(jmp_buf env, int val);
// Restore environment saved by setjmp and return to that point
bool _longjmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [envPtr, val] = *args;

    if (!envPtr)
    {
        std::cerr << "_longjmp: null jmp_buf pointer" << std::endl;
        return false;
    }

    auto *jmpBuf = static_cast<guest::jmp_buf *>( envPtr );

    // Restore registers from jmp_buf (convert from big-endian)
    uint32_t r1 = common::ensure_endianness( jmpBuf->r1, std::endian::big );
    uint32_t r2 = common::ensure_endianness( jmpBuf->r2, std::endian::big );
    uint32_t r13 = common::ensure_endianness( jmpBuf->r13, std::endian::big );
    uint32_t r14 = common::ensure_endianness( jmpBuf->r14, std::endian::big );
    uint32_t r15 = common::ensure_endianness( jmpBuf->r15, std::endian::big );
    uint32_t r16 = common::ensure_endianness( jmpBuf->r16, std::endian::big );
    uint32_t r17 = common::ensure_endianness( jmpBuf->r17, std::endian::big );
    uint32_t r18 = common::ensure_endianness( jmpBuf->r18, std::endian::big );
    uint32_t r19 = common::ensure_endianness( jmpBuf->r19, std::endian::big );
    uint32_t r20 = common::ensure_endianness( jmpBuf->r20, std::endian::big );
    uint32_t r21 = common::ensure_endianness( jmpBuf->r21, std::endian::big );
    uint32_t r22 = common::ensure_endianness( jmpBuf->r22, std::endian::big );
    uint32_t r23 = common::ensure_endianness( jmpBuf->r23, std::endian::big );
    uint32_t r24 = common::ensure_endianness( jmpBuf->r24, std::endian::big );
    uint32_t r25 = common::ensure_endianness( jmpBuf->r25, std::endian::big );
    uint32_t r26 = common::ensure_endianness( jmpBuf->r26, std::endian::big );
    uint32_t r27 = common::ensure_endianness( jmpBuf->r27, std::endian::big );
    uint32_t r28 = common::ensure_endianness( jmpBuf->r28, std::endian::big );
    uint32_t r29 = common::ensure_endianness( jmpBuf->r29, std::endian::big );
    uint32_t r30 = common::ensure_endianness( jmpBuf->r30, std::endian::big );
    uint32_t r31 = common::ensure_endianness( jmpBuf->r31, std::endian::big );
    uint32_t cr = common::ensure_endianness( jmpBuf->cr, std::endian::big );
    uint32_t lr = common::ensure_endianness( jmpBuf->lr, std::endian::big );
    uint32_t ctr = common::ensure_endianness( jmpBuf->ctr, std::endian::big );
    uint32_t xer = common::ensure_endianness( jmpBuf->xer, std::endian::big );

    // Restore all registers
    uc_reg_write( uc, UC_PPC_REG_1, &r1 );
    uc_reg_write( uc, UC_PPC_REG_2, &r2 );
    uc_reg_write( uc, UC_PPC_REG_13, &r13 );
    uc_reg_write( uc, UC_PPC_REG_14, &r14 );
    uc_reg_write( uc, UC_PPC_REG_15, &r15 );
    uc_reg_write( uc, UC_PPC_REG_16, &r16 );
    uc_reg_write( uc, UC_PPC_REG_17, &r17 );
    uc_reg_write( uc, UC_PPC_REG_18, &r18 );
    uc_reg_write( uc, UC_PPC_REG_19, &r19 );
    uc_reg_write( uc, UC_PPC_REG_20, &r20 );
    uc_reg_write( uc, UC_PPC_REG_21, &r21 );
    uc_reg_write( uc, UC_PPC_REG_22, &r22 );
    uc_reg_write( uc, UC_PPC_REG_23, &r23 );
    uc_reg_write( uc, UC_PPC_REG_24, &r24 );
    uc_reg_write( uc, UC_PPC_REG_25, &r25 );
    uc_reg_write( uc, UC_PPC_REG_26, &r26 );
    uc_reg_write( uc, UC_PPC_REG_27, &r27 );
    uc_reg_write( uc, UC_PPC_REG_28, &r28 );
    uc_reg_write( uc, UC_PPC_REG_29, &r29 );
    uc_reg_write( uc, UC_PPC_REG_30, &r30 );
    uc_reg_write( uc, UC_PPC_REG_31, &r31 );
    uc_reg_write( uc, UC_PPC_REG_CR, &cr );
    uc_reg_write( uc, UC_PPC_REG_LR, &lr );
    uc_reg_write( uc, UC_PPC_REG_CTR, &ctr );
    uc_reg_write( uc, UC_PPC_REG_XER, &xer );

    // Set PC to the return address (LR from setjmp)
    uc_reg_write( uc, UC_PPC_REG_PC, &lr );

    // Return val (or 1 if val is 0)
    uint32_t retVal = ( val == 0 ) ? 1 : val;
    if (uc_reg_write( uc, UC_PPC_REG_3, &retVal ) != UC_ERR_OK)
    {
        std::cerr << "Could not write _longjmp return value" << std::endl;
        return false;
    }

    return true;
}

bool keymgr_dwarf2_register_sections( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

bool cthread_init_routine( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

bool dyld_make_delayed_module_initializer_calls( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    static constexpr std::uint8_t Stack_Frame_Size{ 0x20 };
    static constexpr std::array<std::uint8_t, 12> prolog{
        0x7C, 0x08, 0x02, 0xA6,                     // mflr      r0
        0x90, 0x01, 0x00, 0x08,                     // stw r0, 8( r1 )
        0x94, 0x21, 0xFF, 0x100 - Stack_Frame_Size, // stwu r1 -0x20( r1 )
    };
    static constexpr std::array<std::uint8_t, 16> epilog{
        0x80, 0x01, 0x00, Stack_Frame_Size + 8, // lwz       r0, 0x28(r1)
        0x38, 0x21, 0x00, Stack_Frame_Size,     // addi      r1, r1, 0x20
        0x7C, 0x08, 0x03, 0xA6,                 // mtlr      r0
        0x4E, 0x80, 0x00, 0x20,                 // blr
    };
    static constexpr std::array<std::uint8_t, 16> constructor_call{
        0x3D, 0x80, 0x00, 0x00, // lis r12,XXXX (FUNC1 hi)  <-- patch
        0x39, 0x8C, 0x00, 0x00, // addi r12,r12,XXXX (FUNC1 lo) <-- patch
        0x7D, 0x89, 0x03, 0xA6, // mtctr r12
        0x4E, 0x80, 0x04, 0x21, // bctrl
    };

    std::vector<std::uint8_t> trampoline_mem{};
    std::copy( prolog.begin(), prolog.end(), std::back_inserter( trampoline_mem ) );

    std::vector<std::uint32_t> static_constructor_arr{ loader->get_static_constructors() };
    for (const std::uint32_t constructor_va : static_constructor_arr)
    {
        std::array<uint8_t, 16> current_constructor_call{ constructor_call };
        std::uint16_t hi{ static_cast<std::uint16_t>( ( constructor_va + 0x8000 ) >> 16 ) };
        std::uint16_t lo{ static_cast<std::uint16_t>( constructor_va & 0xFFFF ) };
        current_constructor_call[2] = static_cast<std::uint8_t>( hi >> 8 );
        current_constructor_call[3] = static_cast<std::uint8_t>( hi & 0xFF );
        current_constructor_call[6] = static_cast<std::uint8_t>( lo >> 8 );
        current_constructor_call[7] = static_cast<std::uint8_t>( lo & 0xFF );
        std::copy( current_constructor_call.begin(), current_constructor_call.end(),
                   std::back_inserter( trampoline_mem ) );
    }
    std::copy( epilog.begin(), epilog.end(), std::back_inserter( trampoline_mem ) );

    std::uint32_t trampoline_guest_addr{ mem->heap_alloc( trampoline_mem.size() ) };
    void *trampoline_host_addr{ reinterpret_cast<void *>( mem->to_host( trampoline_guest_addr ) ) };

    std::memcpy( trampoline_host_addr, trampoline_mem.data(), trampoline_mem.size() );

    if (uc_reg_write( uc, UC_PPC_REG_PC, &trampoline_guest_addr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write trampoline return address" << std::endl;
        return false;
    }
    return true;
}

// int _dyld_func_lookup(const char *dyld_func_name, void **address);
bool dyld_func_lookup( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, uint64_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [namePtr, callbackAddress] = *args;
    std::string name( namePtr );

    std::optional<uint32_t> importEntryVa{ common::get_import_entry_va_by_name( name ) };
    if (!importEntryVa.has_value())
        // TODO fix? crt1 code check for null every function except __dyld_make_delayed_module_initializer_calls
        importEntryVa.emplace( 0 );
    else
        *importEntryVa += sizeof( uint32_t ); // + sizeof(uint32_t) as it is direct import

    uint32_t callbackAddressBe{ common::ensure_endianness( *importEntryVa, std::endian::big ) };
    if (uc_mem_write( uc, callbackAddress, &callbackAddressBe, sizeof( callbackAddressBe ) ) != UC_ERR_OK)
    {
        std::cerr << "Could not write dyld_func_lookup resolved address to memory" << std::endl;
        return false;
    }
    return true;
}

// int abs(int n);
bool abs( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [n] = *args;

    int ret{ ::abs( n ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write abs return value" << std::endl;
        return false;
    }
    return true;
}

// int atexit(void (*func)(void));
bool atexit( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

// int atoi(const char *str);
// Converts string to integer
bool atoi( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str] = *args;

    // Use standard C library atoi
    int result = ::atoi( str );

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write atoi return value" << std::endl;
        return false;
    }
    return true;
}

bool exit( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    uc_emu_stop( uc );
    return true;
}

// pid_t fork(void);
// Shim: always returns 0 (pretend to be the child process)
bool fork( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    std::cout << "[OsxPpcEmu] fork() shim called, returning 0 (child)" << std::endl;
    std::uint32_t ret{ 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fork return value" << std::endl;
        return false;
    }
    return true;
}

// int execve(const char *path, char *const argv[], char *const envp[]);
// Redirects execution of PPC binaries through the emulator
bool execve( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, std::uint32_t, std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, guestArgvAddr, guestEnvpAddr] = *args;

    // Resolve the emulator's own executable path
    char emuPath[4096]{};
    std::uint32_t emuPathSize{ sizeof( emuPath ) };
#ifdef __APPLE__
    bool resolved{ _NSGetExecutablePath( emuPath, &emuPathSize ) == 0 };
#else
    ssize_t len{ ::readlink( "/proc/self/exe", emuPath, sizeof( emuPath ) - 1 ) };
    bool resolved{ len != -1 };
    if (resolved)
        emuPath[len] = '\0';
#endif
    if (!resolved)
    {
        std::cerr << "[OsxPpcEmu] execve: could not resolve emulator path" << std::endl;
        set_guest_errno( mem, ENOENT );
        std::int32_t ret{ -1 };
        uc_reg_write( uc, UC_PPC_REG_3, &ret );
        return true;
    }

    // Read null-terminated guest argv: array of big-endian 32-bit pointers
    std::vector<const char *> guestArgv;
    for (std::uint32_t cur{ guestArgvAddr }; cur != 0;)
    {
        std::uint32_t ptrBe{};
        ::memcpy( &ptrBe, mem->get( cur ), sizeof( ptrBe ) );
        std::uint32_t ptr{ common::ensure_endianness( ptrBe, std::endian::big ) };
        if (ptr == 0)
            break;
        guestArgv.push_back( reinterpret_cast<const char *>( mem->get( ptr ) ) );
        cur += 4;
    }

    // Build new argv: emulator, target binary, then original args (skip argv[0])
    std::vector<const char *> newArgv{ emuPath, path };
    for (std::size_t i{ 1 }; i < guestArgv.size(); ++i)
        newArgv.push_back( guestArgv[i] );
    newArgv.push_back( nullptr );

    std::cout << "[OsxPpcEmu] execve: redirecting " << path << " through " << emuPath << std::endl;

    ::execv( emuPath, const_cast<char *const *>( newArgv.data() ) );

    // Only reached on failure
    std::cerr << "[OsxPpcEmu] execve failed: " << ::strerror( errno ) << std::endl;
    set_guest_errno( mem, errno );
    std::int32_t ret{ -1 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write execve return value" << std::endl;
        return false;
    }
    return true;
}

// int fclose(FILE *stream);
bool fclose( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );
    int ret{ ::fclose( f ) };

    if (ret == EOF)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fgetc return value" << std::endl;
        return false;
    }
    return true;
}

// int fflush(FILE *stream);
bool fflush( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    int ret{ ::fflush( f ) };

    if (ret == EOF)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fflush return value" << std::endl;
        return false;
    }
    return true;
}

// int fgetc(FILE *stream);
bool fgetc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    int ret{ ::fgetc( f ) };

    if (ret == EOF)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fgetc return value" << std::endl;
        return false;
    }
    return true;
}

// FILE *fopen(const char *filename, const char *mode);
bool fopen( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [filename, mode] = *args;

    FILE *ret{ ::fopen( filename, mode ) };

    if (ret == nullptr)
    {
        set_guest_errno( mem, errno );
    }

    // Store the FILE* in guest memory and return pointer to it
    uint32_t retGuest{ 0 };
    if (ret != nullptr)
    {
        // Allocate space for the FILE* on the heap
        retGuest = mem->heap_alloc( sizeof( FILE * ) );
        if (retGuest != 0)
        {
            FILE **filePtr{ static_cast<FILE **>( mem->get( retGuest ) ) };
            if (filePtr)
            {
                *filePtr = ret;
            }
            else
            {
                ::fclose( ret );
                retGuest = 0;
            }
        }
        else
        {
            ::fclose( ret );
        }
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fopen return value" << std::endl;
        return false;
    }
    return true;
}

// size_t fwrite( const void * buffer, size_t size, size_t count, FILE * stream );
bool fwrite( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const void *, std::size_t, std::size_t, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buffer, size, count, stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    std::size_t ret{ ::fwrite( buffer, size, count, f ) };

    // fwrite returns less than count on error
    if (ret < count)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fwrite return value" << std::endl;
        return false;
    }
    return true;
}

// int fstat(int fd, struct stat *buf);
bool fstat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd, buf] = *args;

    struct stat hostStat{};
    int ret{ ::fstat( fd, &hostStat ) };

    if (ret == 0 && buf != nullptr)
    {
        auto *guestStat{ static_cast<guest::stat *>( buf ) };
        ::memset( guestStat, 0, sizeof( guest::stat ) );
        guestStat->st_dev = common::ensure_endianness( hostStat.st_dev, std::endian::big );
        guestStat->st_ino = common::ensure_endianness( hostStat.st_ino, std::endian::big );
        guestStat->st_mode = common::ensure_endianness( hostStat.st_mode, std::endian::big );
        guestStat->st_nlink = common::ensure_endianness( hostStat.st_nlink, std::endian::big );
        guestStat->st_uid = common::ensure_endianness( hostStat.st_uid, std::endian::big );
        guestStat->st_gid = common::ensure_endianness( hostStat.st_gid, std::endian::big );
        guestStat->st_rdev = common::ensure_endianness( hostStat.st_rdev, std::endian::big );
        guestStat->st_size = common::ensure_endianness( hostStat.st_size, std::endian::big );
        guestStat->st_blksize = common::ensure_endianness( hostStat.st_blksize, std::endian::big );
        guestStat->st_blocks = common::ensure_endianness( hostStat.st_blocks, std::endian::big );
    }
    else if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fstat return value" << std::endl;
        return false;
    }
    return true;
}

// int ioctl(int fd, unsigned long op, ...);
bool ioctl( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, uint32_t, void *>( uc, mem ) };
    if (!args.has_value())
        return false;

    const auto [fd, op, ptr]{ *args };

    static constexpr std::uint32_t Get_Window_Size_Op{ 0x40087468 };
    struct winsize
    {
        unsigned short ws_row;    /* rows, in characters */
        unsigned short ws_col;    /* columns, in characters */
        unsigned short ws_xpixel; /* horizontal size, pixels */
        unsigned short ws_ypixel; /* vertical size, pixels */
    };
    std::int32_t ret{};
    if (op == Get_Window_Size_Op)
    {
        reinterpret_cast<winsize *>( ptr )->ws_row = common::ensure_endianness<short>( 25, std::endian::big );
        reinterpret_cast<winsize *>( ptr )->ws_col = common::ensure_endianness<short>( 80, std::endian::big );
        reinterpret_cast<winsize *>( ptr )->ws_xpixel = 0;
        reinterpret_cast<winsize *>( ptr )->ws_ypixel = 0;
        ret = 0;
    }
    else
    {
        ret = -1;
        assert( "Missing implementation for ioctl" );
    }
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write malloc return" << std::endl;
        return false;
    }
    return true;
}

bool mach_init_routine( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

// void* malloc(std::size_t size);
bool malloc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [size]{ *args };

    uint32_t ret{ mem->heap_alloc( size ) };

    // Set errno if allocation failed
    if (ret == 0)
    {
        set_guest_errno( mem, ENOMEM );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write malloc return" << std::endl;
        return false;
    }
    return true;
}

// void* calloc(std::size_t num, std::size_t size);
bool calloc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::size_t, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [num, size]{ *args };

    uint32_t ret{ mem->heap_alloc( num * size ) };
    // calloc zeros the memory
    void *ptr{ mem->get( ret ) };
    if (ptr)
        ::memset( ptr, 0, num * size );
    else if (ret == 0)
    {
        set_guest_errno( mem, ENOMEM );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write calloc return" << std::endl;
        return false;
    }
    return true;
}

// void* realloc(void* ptr, std::size_t size);
bool realloc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [ptr, size]{ *args };

    // If ptr is NULL, realloc behaves like malloc
    if (!ptr)
    {
        uint32_t ret{ mem->heap_alloc( size ) };
        if (ret == 0)
        {
            set_guest_errno( mem, ENOMEM );
        }
        if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write realloc return" << std::endl;
            return false;
        }
        return true;
    }

    // If size is 0, realloc behaves like free (but we return NULL since we don't actually free)
    if (size == 0)
    {
        uint32_t ret{ 0 };
        if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write realloc return" << std::endl;
            return false;
        }
        return true;
    }

    // Allocate new memory and copy old data
    uint32_t oldGuestPtr{ mem->to_guest( ptr ) };
    std::size_t oldSize{ mem->get_alloc_size( oldGuestPtr ) };

    uint32_t newPtr{ mem->heap_alloc( size ) };
    void *newHostPtr{ mem->get( newPtr ) };

    if (newHostPtr && ptr)
    {
        // Copy old data to new location
        // Copy the minimum of old size and new size to avoid reading/writing out of bounds
        std::size_t copySize{ oldSize > 0 ? std::min( oldSize, size ) : size };
        ::memcpy( newHostPtr, ptr, copySize );
    }
    else if (newPtr == 0)
    {
        set_guest_errno( mem, ENOMEM );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &newPtr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write realloc return" << std::endl;
        return false;
    }
    return true;
}

// void* memcpy(void * destination, const void * source, size_t num);
bool memcpy( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, const void *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, count] = *args;
    ::memcpy( dest, source, count );
    uint32_t retGuest{ mem->to_guest( dest ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memcpy return" << std::endl;
        return false;
    }
    return true;
}

// void* memmove( void* dest, const void* src, std::size_t count );
bool memmove( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, const void *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, count] = *args;
    ::memmove( dest, source, count );
    uint32_t retGuest{ mem->to_guest( dest ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memmove return" << std::endl;
        return false;
    }
    return true;
}

// void *memset(void *str, int c, size_t n)
bool memset( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, int, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, c, n] = *args;
    ::memset( str, c, n * sizeof( char ) );
    uint32_t retGuest{ mem->to_guest( str ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memset return" << std::endl;
        return false;
    }
    return true;
}

// int puts(const char *str);
bool puts( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str] = *args;
    int ret{ ::puts( str ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write puts return value" << std::endl;
        return false;
    }
    return true;
}

// int setvbuf( FILE * stream, char * buffer, int mode, size_t size );
bool setvbuf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, char *, int, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    // TODO
    uint32_t success{ 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &success ) != UC_ERR_OK)
    {
        std::cerr << "Could not write return value of setvbuf" << std::endl;
        return false;
    }
    return true;
}

// sighandler_t signal(int signum, sighandler_t handler);
bool signal( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    // TODO
    return true;
}

// int sprintf(char * buffer, const char * format, ...);
bool sprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;

    auto [buffer, format]{ *args };

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_5, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsprintf( buffer, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write sprintf return value" << std::endl;
        return false;
    }
    return true;
}

// int printf(const char *format, ...)
bool printf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    auto [format]{ *args };

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_4, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vprintf( format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write printf return value" << std::endl;
        return false;
    }
    return true;
}

// int vsprintf(char * buffer, const char * format, va_list ap);
bool vsprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto &[s, format, apPtr] = *args;
    std::vector formatArgs{ common::get_va_arguments( mem, apPtr, format ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsprintf( s, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write vsprintf return value" << std::endl;
        return false;
    }
    return true;
}

// int stat(const char * restrict path,	struct stat * restrict sb);
bool stat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, sb] = *args;

    // Call host stat
    struct stat hostStat;
    int ret{ ::stat( path, &hostStat ) };

    if (ret == 0 && sb != nullptr)
    {
        auto *guestStat{ static_cast<guest::stat *>( sb ) };
        guestStat->st_dev = common::ensure_endianness( hostStat.st_dev, std::endian::big );
        guestStat->st_ino = common::ensure_endianness( hostStat.st_ino, std::endian::big );
        guestStat->st_mode = common::ensure_endianness( hostStat.st_mode, std::endian::big );
        guestStat->st_nlink = common::ensure_endianness( hostStat.st_nlink, std::endian::big );
        guestStat->st_uid = common::ensure_endianness( hostStat.st_uid, std::endian::big );
        guestStat->st_gid = common::ensure_endianness( hostStat.st_gid, std::endian::big );
        guestStat->st_rdev = common::ensure_endianness( hostStat.st_rdev, std::endian::big );
        guestStat->st_size = common::ensure_endianness( hostStat.st_size, std::endian::big );
        guestStat->st_blksize = common::ensure_endianness( hostStat.st_blksize, std::endian::big );
        guestStat->st_blocks = common::ensure_endianness( hostStat.st_blocks, std::endian::big );
    }
    else if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write stat return value" << std::endl;
        return false;
    }
    return true;
}

// int lstat(const char * restrict path, struct stat * restrict sb);
// Like stat but doesn't follow symbolic links
bool lstat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, sb] = *args;

    // Call host lstat
    struct stat hostStat{};
    int ret{ ::lstat( path, &hostStat ) };

    if (ret == 0 && sb != nullptr)
    {
        auto *guestStat{ static_cast<guest::stat *>( sb ) };
        guestStat->st_dev = common::ensure_endianness( hostStat.st_dev, std::endian::big );
        guestStat->st_ino = common::ensure_endianness( hostStat.st_ino, std::endian::big );
        guestStat->st_mode = common::ensure_endianness( hostStat.st_mode, std::endian::big );
        guestStat->st_nlink = common::ensure_endianness( hostStat.st_nlink, std::endian::big );
        guestStat->st_uid = common::ensure_endianness( hostStat.st_uid, std::endian::big );
        guestStat->st_gid = common::ensure_endianness( hostStat.st_gid, std::endian::big );
        guestStat->st_rdev = common::ensure_endianness( hostStat.st_rdev, std::endian::big );
        guestStat->st_size = common::ensure_endianness( hostStat.st_size, std::endian::big );
        guestStat->st_blksize = common::ensure_endianness( hostStat.st_blksize, std::endian::big );
        guestStat->st_blocks = common::ensure_endianness( hostStat.st_blocks, std::endian::big );
    }
    else if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write lstat return value" << std::endl;
        return false;
    }
    return true;
}

// char * strcat( char * destination, const char * source );
bool strcat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, src] = *args;
    char *ret{ ::strcat( dest, src ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcat return value" << std::endl;
        return false;
    }
    return true;
}

// char * strchr( const char * str, int ch );
bool strchr( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, ch] = *args;
    char *ret{ ::strchr( str, ch ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strchr return value" << std::endl;
        return false;
    }
    return true;
}

// size_t strlen( const char * str );
bool strlen( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str] = *args;
    std::size_t ret{ ::strlen( str ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strlen return value" << std::endl;
        return false;
    }
    return true;
}

// char *strpbrk(const char *str1, const char *str2);
// Finds the first character in str1 that matches any character in str2
bool strpbrk( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str1, str2] = *args;
    const char *ret{ ::strpbrk( str1, str2 ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strpbrk return value" << std::endl;
        return false;
    }
    return true;
}

// char * strrchr( const char * str, int ch );
bool strrchr( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, ch] = *args;

    char *ret{ ::strrchr( str, ch ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strrchr return value" << std::endl;
        return false;
    }
    return true;
}

// char *strstr(const char *haystack, const char *needle);
bool strstr( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [haystack, needle] = *args;

    const char *ret{ ::strstr( haystack, needle ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strstr return value" << std::endl;
        return false;
    }
    return true;
}

// char *strcpy( char *dest, const char *src );
bool strcpy( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source] = *args;

    char *ret{ ::strcpy( dest, source ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcpy return value" << std::endl;
        return false;
    }
    return true;
}

// char *strdup( const char *s );
// Duplicates a string by allocating memory and copying the contents
bool strdup( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str] = *args;

    if (!str)
    {
        uint32_t ret{ 0 };
        if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write strdup return value" << std::endl;
            return false;
        }
        return true;
    }

    std::size_t len{ ::strlen( str ) };
    uint32_t guestPtr{ mem->heap_alloc( len + 1 ) };

    if (guestPtr == 0)
    {
        set_guest_errno( mem, ENOMEM );
        if (uc_reg_write( uc, UC_PPC_REG_3, &guestPtr ) != UC_ERR_OK)
        {
            std::cerr << "Could not write strdup return value" << std::endl;
            return false;
        }
        return true;
    }

    char *dest{ static_cast<char *>( mem->get( guestPtr ) ) };
    if (dest)
    {
        ::memcpy( dest, str, len + 1 );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &guestPtr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strdup return value" << std::endl;
        return false;
    }
    return true;
}

// char *strerror(int errnum);
// Returns a pointer to the textual representation of the current errno value
bool strerror( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [errnum] = *args;

    const char *ret{ ::strerror( errnum ) };
    uint32_t retGuest{ 0 };

    if (ret != nullptr)
    {
        std::size_t len{ ::strlen( ret ) + 1 };
        char *heap_ptr{ reinterpret_cast<char *>( mem->to_host( mem->heap_alloc( len ) ) ) };
        ::memcpy( heap_ptr, ret, len );
        retGuest = mem->to_guest( heap_ptr );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strerror return value" << std::endl;
        return false;
    }
    return true;
}

// char * strncpy ( char * destination, const char * source, size_t num );
bool strncpy( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, num] = *args;

    char *ret{ ::strncpy( dest, source, num ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncpy return value" << std::endl;
        return false;
    }
    return true;
}

bool dyld_stub_binding_helper( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

bool vsnprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, size_t, const char *, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto &[s, n, format, apPtr] = *args;
    std::vector formatArgs{ common::get_va_arguments( mem, apPtr, format ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsnprintf( s, n, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write vsnprintf return value" << std::endl;
        return false;
    }
    return true;
}

// char *getcwd(char *buf, size_t size);
bool getcwd( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buf, size] = *args;
    char *ret{ ::getcwd( buf, size ) };

    if (ret == nullptr)
    {
        set_guest_errno( mem, errno );
    }

    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write getcwd return value" << std::endl;
        return false;
    }
    return true;
}

// void free(void *ptr);
bool free( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    // Do not actually free memory
    return true;
}

// int strcmp( const char *lhs, const char *rhs );
bool strcmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [lhs, rhs] = *args;
    int ret{ ::strcmp( lhs, rhs ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcmp return value" << std::endl;
        return false;
    }
    return true;
}

// int strncmp(const char *s1, const char *s2, size_t n);
bool strncmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [s1, s2, n] = *args;
    int ret{ ::strncmp( s1, s2, n ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncmp return value" << std::endl;
        return false;
    }
    return true;
}

// int fprintf(FILE *stream, const char *format, ...);
bool fprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;

    auto [stream, format]{ *args };

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_5, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vfprintf( f, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fprintf return value" << std::endl;
        return false;
    }
    return true;
}

// ssize_t readlink(const char *path, char *buf, size_t bufsiz);
bool readlink( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, buf, bufsiz] = *args;

    ssize_t ret{ ::readlink( path, buf, bufsiz ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    std::int32_t retVal{ static_cast<std::int32_t>( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retVal ) != UC_ERR_OK)
    {
        std::cerr << "Could not write readlink return value" << std::endl;
        return false;
    }
    return true;
}

// off_t lseek(int fd, off_t offset, int whence);
bool lseek( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, std::uint32_t, std::uint32_t, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd, offsetHi, offsetLo, whence] = *args;

    std::int64_t offset{ offsetLo | ( static_cast<std::int64_t>( offsetHi ) << 32 ) };
    off_t ret{ ::lseek( fd, static_cast<off_t>( offset ), whence ) };

    if (ret == static_cast<off_t>( -1 ))
    {
        set_guest_errno( mem, errno );
    }

    uint32_t retGuest = static_cast<uint32_t>( ret );
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write lseek return value" << std::endl;
        return false;
    }
    return true;
}

// char *getenv(const char *name);
bool getenv( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [name] = *args;

    char *ret{ ::getenv( name ) };
    uint32_t retGuest{ 0 };
    if (name != nullptr && std::strlen( name ) >= 7 && !std::memcmp( name, "DISPLAY", 7 ))
    {
        static constexpr std::string_view retStr{ ":0" };
        char *heap_ptr{ reinterpret_cast<char *>( mem->to_host( mem->heap_alloc( retStr.size() + 1 ) ) ) };
        ::memcpy( heap_ptr, retStr.data(), retStr.size() );
        heap_ptr[retStr.size()] = '\0';
        retGuest = mem->to_guest( heap_ptr );
    }
    else if (ret != nullptr)
    {
        char *heap_ptr{ reinterpret_cast<char *>( mem->to_host( mem->heap_alloc( ::strlen( ret ) + 1 ) ) ) };
        ::memcpy( heap_ptr, ret, ::strlen( ret ) + 1 );
        retGuest = mem->to_guest( heap_ptr );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write getenv return value" << std::endl;
        return false;
    }
    return true;
}

// int open(const char *path, int flags, ...);
bool open( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, int, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, flags, mode] = *args;

    int ret{ ::open( path, flags, mode ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write open return value" << std::endl;
        return false;
    }
    return true;
}

// DIR *opendir(const char *path);
bool opendir( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path] = *args;

    DIR *hostDir{ ::opendir( path ) };

    std::uint32_t retPtr{ 0 };
    if (hostDir == nullptr)
    {
        set_guest_errno( mem, errno );
    }
    else
    {
        DIR *hostDirDst{ reinterpret_cast<DIR *>( mem->to_host( mem->heap_alloc( sizeof( DIR ) ) ) ) };
        ::memcpy( hostDirDst, hostDir, sizeof( DIR ) );
        retPtr = mem->to_guest( hostDirDst );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &retPtr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write opendir return value" << std::endl;
        return false;
    }
    return true;
}

// struct dirent *readdir(DIR *dirp);
bool readdir( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [guestDirPtr] = *args;

    std::uint32_t retPtr{ 0 };
    if (guestDirPtr == 0)
    {
        set_guest_errno( mem, EBADF );
    }
    else
    {
        DIR *hostDir{ reinterpret_cast<DIR *>( mem->to_host( guestDirPtr ) ) };
        struct dirent *hostEntry{ ::readdir( hostDir ) };

        if (hostEntry == nullptr)
        {
            if (errno != 0)
                set_guest_errno( mem, errno );
            // NULL return with errno=0 means end of directory
        }
        else
        {
            std::uint32_t guestEntryVa{ mem->heap_alloc( sizeof( guest::dirent ) ) };
            guest::dirent *guestEntry{ reinterpret_cast<guest::dirent *>( mem->to_host( guestEntryVa ) ) };
            if (!guestEntry)
            {
                set_guest_errno( mem, ENOMEM );
            }
            else
            {
                std::memset( guestEntry, 0, sizeof( guest::dirent ) );
                guestEntry->d_ino =
                    common::ensure_endianness( static_cast<uint32_t>( hostEntry->d_ino ), std::endian::big );
                guestEntry->d_reclen =
                    common::ensure_endianness( static_cast<uint16_t>( hostEntry->d_reclen ), std::endian::big );
                guestEntry->d_type = hostEntry->d_type;
                guestEntry->d_namlen =
                    common::ensure_endianness( static_cast<uint16_t>( hostEntry->d_namlen ), std::endian::big );
                std::strncpy( guestEntry->d_name, hostEntry->d_name, sizeof( guestEntry->d_name ) - 1 );
                guestEntry->d_name[sizeof( guestEntry->d_name ) - 1] = '\0';

                retPtr = guestEntryVa;
            }
        }
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &retPtr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write readdir return value" << std::endl;
        return false;
    }
    return true;
}

// int closedir(DIR *dirp);
bool closedir( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [guestDir] = *args;

    int ret{ 0 };
    if (guestDir == 0)
    {
        set_guest_errno( mem, EBADF );
    }
    else
    {
        // no ::closedir as it calls free on non heap address
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write closedir return value" << std::endl;
        return false;
    }
    return true;
}

// int unlink(const char *pathname);
// Deletes a name from the filesystem
bool unlink( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [pathname] = *args;

    int ret{ ::unlink( pathname ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write unlink return value" << std::endl;
        return false;
    }

    return true;
}

// int utime(const char *filename, const struct utimbuf *times);
// Set file access and modification times
// TODO fix, not working, bad date, why?
bool utime( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [filename, times] = *args;

    const guest::utimbuf *timesPtr{ reinterpret_cast<const guest::utimbuf *>( times ) };
    utimbuf hostTimes{};
    if (times != nullptr)
    {
        hostTimes.actime = common::ensure_endianness( static_cast<std::int32_t>( timesPtr->actime ), std::endian::big );
        hostTimes.modtime =
            common::ensure_endianness( static_cast<std::int32_t>( timesPtr->modtime ), std::endian::big );
    }

    int ret{ ::utime( filename, &hostTimes ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write utime return value" << std::endl;
        return false;
    }
    return true;
}

// int chmod(const char *path, mode_t mode);
bool chmod( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, mode] = *args;

    int ret{ ::chmod( path, static_cast<mode_t>( mode ) ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write chmod return value" << std::endl;
        return false;
    }
    return true;
}

// int close(int fd);
bool close( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd] = *args;

    int ret{ ::close( fd ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write close return value" << std::endl;
        return false;
    }
    return true;
}

// ssize_t read(int fd, void *buf, size_t count);
bool read( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, void *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd, buf, count] = *args;

    ssize_t ret{ ::read( fd, buf, count ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    std::int32_t retVal{ static_cast<std::int32_t>( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retVal ) != UC_ERR_OK)
    {
        std::cerr << "Could not write read return value" << std::endl;
        return false;
    }
    return true;
}

// ssize_t write(int fd, const void *buf, size_t count);
bool write( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, const void *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd, buf, count] = *args;

    ssize_t ret{ ::write( fd, buf, count ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write write return value" << std::endl;
        return false;
    }
    return true;
}

// int memcmp(const void *s1, const void *s2, size_t n);
bool memcmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const void *, const void *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [s1, s2, n] = *args;

    int ret{ ::memcmp( s1, s2, n ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memcmp return value" << std::endl;
        return false;
    }
    return true;
}

// time_t time(time_t *tloc);
bool time( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<time_t *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [tloc] = *args;

    time_t ret{ ::time( nullptr ) };
    std::uint32_t guestTime{ common::ensure_endianness( static_cast<std::uint32_t>( ret ), std::endian::big ) };
    if (tloc != nullptr)
    {
        ::memcpy( tloc, &guestTime, sizeof( guestTime ) );
    }

    std::uint32_t retNative{ static_cast<std::uint32_t>( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retNative ) != UC_ERR_OK)
    {
        std::cerr << "Could not write time return value" << std::endl;
        return false;
    }
    return true;
}

// clock_t times(struct tms *buf);
bool times( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    // TODO
    /*
    const auto args{ get_arguments<struct tms *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buf] = *args;

    clock_t ret{ ::times( buf ) };
    std::uint32_t guestRet{ common::ensure_endianness( static_cast<std::uint32_t>( ret ), std::endian::big ) };
    if (ret == static_cast<clock_t>( -1 ))
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &guestRet ) != UC_ERR_OK)
    {
        std::cerr << "Could not write times return value" << std::endl;
        return false;
    }
    */
    return true;
}

// char *tmpnam(char *s);
bool tmpnam( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [s] = *args;

    char *ret{ ::tmpnam( s ) };

    std::uint32_t guestRet{ ret ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &guestRet ) != UC_ERR_OK)
    {
        std::cerr << "Could not write tmpnam return value" << std::endl;
        return false;
    }
    return true;
}

// int getdtablesize(void);
bool getdtablesize( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    int ret{ ::getdtablesize() };
    std::uint32_t retGuest{ static_cast<std::uint32_t>( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write getdtablesize return value" << std::endl;
        return false;
    }
    return true;
}

// mode_t umask(mode_t mask);
bool umask( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [mask] = *args;

    mode_t ret{ ::umask( static_cast<mode_t>( mask ) ) };
    uint32_t retGuest = static_cast<uint32_t>( ret );

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write umask return value" << std::endl;
        return false;
    }
    return true;
}

// struct tm *localtime(const time_t *timep);
bool localtime( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const time_t *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [timep] = *args;

    // Read the time_t value from guest memory (big-endian)
    time_t hostTime{};
    if (timep != nullptr)
    {
        uint32_t guestTime;
        ::memcpy( &guestTime, timep, sizeof( guestTime ) );
        hostTime = static_cast<time_t>( common::ensure_endianness( guestTime, std::endian::big ) );
    }
    else
    {
        hostTime = ::time( nullptr );
    }
    struct tm *ret{ ::localtime( &hostTime ) };
    void *zone_ptr{ nullptr };
    if (ret->tm_zone != nullptr)
    {
        zone_ptr = reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( ::strlen( ret->tm_zone ) + 1 ) ) );
        ::memcpy( zone_ptr, ret->tm_zone, ::strlen( ret->tm_zone ) + 1 );
    }
    guest::tm tmGuest{ .tm_sec = common::ensure_endianness( ret->tm_sec, std::endian::big ),
                       .tm_min = common::ensure_endianness( ret->tm_min, std::endian::big ),
                       .tm_hour = common::ensure_endianness( ret->tm_hour, std::endian::big ),
                       .tm_mday = common::ensure_endianness( ret->tm_mday, std::endian::big ),
                       .tm_mon = common::ensure_endianness( ret->tm_mon, std::endian::big ),
                       .tm_year = common::ensure_endianness( ret->tm_year, std::endian::big ),
                       .tm_wday = common::ensure_endianness( ret->tm_wday, std::endian::big ),
                       .tm_yday = common::ensure_endianness( ret->tm_yday, std::endian::big ),
                       .tm_isdst = common::ensure_endianness( ret->tm_isdst, std::endian::big ),
                       .tm_gmtoff =
                           common::ensure_endianness( static_cast<std::int32_t>( ret->tm_gmtoff ), std::endian::big ),
                       .tm_zone = mem->to_guest( zone_ptr ) };
    void *retPtrHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( sizeof( guest::tm ) ) ) ) };
    ::memcpy( retPtrHost, &tmGuest, sizeof( guest::tm ) );
    uint32_t retGuest{ mem->to_guest( retPtrHost ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write localtime return value" << std::endl;
        return false;
    }
    return true;
}

// struct hostent *gethostbyname(const char *name);
bool gethostbyname( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [name] = *args;

    struct hostent *ret{ ::gethostbyname( name ) };

    if (!ret)
    {
        uint32_t nullPtr{ 0 };
        if (uc_reg_write( uc, UC_PPC_REG_3, &nullPtr ) != UC_ERR_OK)
        {
            std::cerr << "Could not write gethostbyname return value" << std::endl;
            return false;
        }
        return true;
    }
    uint32_t namePtr{ 0 };
    if (ret->h_name)
    {
        size_t nameLen{ ::strlen( ret->h_name ) + 1 };
        void *nameHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( nameLen ) ) ) };
        ::memcpy( nameHost, ret->h_name, nameLen );
        namePtr = mem->to_guest( nameHost );
    }

    uint32_t aliasesPtr{ 0 };
    if (ret->h_aliases)
    {
        size_t aliasCount{ 0 };
        while (ret->h_aliases[aliasCount])
            aliasCount++;

        // Allocate array of guest pointers (aliasCount + 1 for NULL terminator)
        void *aliasArrayHost{
            reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( ( aliasCount + 1 ) * sizeof( uint32_t ) ) ) ) };
        uint32_t *aliasArray{ static_cast<uint32_t *>( aliasArrayHost ) };

        for (size_t i = 0; i < aliasCount; i++)
        {
            size_t aliasLen{ ::strlen( ret->h_aliases[i] ) + 1 };
            void *aliasHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( aliasLen ) ) ) };
            ::memcpy( aliasHost, ret->h_aliases[i], aliasLen );
            aliasArray[i] = common::ensure_endianness( mem->to_guest( aliasHost ), std::endian::big );
        }
        aliasArray[aliasCount] = 0; // NULL terminator
        aliasesPtr = mem->to_guest( aliasArrayHost );
    }

    uint32_t addrListPtr{ 0 };
    if (ret->h_addr_list)
    {
        size_t addrCount{ 0 };
        while (ret->h_addr_list[addrCount])
            addrCount++;

        // Allocate array of guest pointers (addrCount + 1 for NULL terminator)
        void *addrArrayHost{
            reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( ( addrCount + 1 ) * sizeof( uint32_t ) ) ) ) };
        uint32_t *addrArray{ static_cast<uint32_t *>( addrArrayHost ) };

        for (size_t i = 0; i < addrCount; i++)
        {
            void *addrHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( ret->h_length ) ) ) };
            ::memcpy( addrHost, ret->h_addr_list[i], ret->h_length );
            addrArray[i] = common::ensure_endianness( mem->to_guest( addrHost ), std::endian::big );
        }
        addrArray[addrCount] = 0; // NULL terminator
        addrListPtr = mem->to_guest( addrArrayHost );
    }

    guest::hostent guestHostent{ .h_name = common::ensure_endianness( namePtr, std::endian::big ),
                                 .h_aliases = common::ensure_endianness( aliasesPtr, std::endian::big ),
                                 .h_addrtype = common::ensure_endianness( ret->h_addrtype, std::endian::big ),
                                 .h_length = common::ensure_endianness( ret->h_length, std::endian::big ),
                                 .h_addr_list = common::ensure_endianness( addrListPtr, std::endian::big ) };

    void *hostentHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( sizeof( guest::hostent ) ) ) ) };
    ::memcpy( hostentHost, &guestHostent, sizeof( guest::hostent ) );
    uint32_t hostentGuest{ mem->to_guest( hostentHost ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &hostentGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write gethostbyname return value" << std::endl;
        return false;
    }
    return true;
}

// int gethostname(char *name, size_t namelen);
bool gethostname( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [name, namelen] = *args;

    int ret{ ::gethostname( name, namelen ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write gethostname return value" << std::endl;
        return false;
    }
    return true;
}

// int ungetc( int character, FILE * stream );
bool ungetc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [character, stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );
    int ret{ ::ungetc( character, f ) };

    if (ret == EOF)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write gethostname return value" << std::endl;
        return false;
    }
    return true;
}

// int sscanf(const char *str, const char *format, ...);
bool sscanf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, format] = *args;

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_5, true ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsscanf( str, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write sscanf return value" << std::endl;
        return false;
    }
    return true;
}

// time_t mktime(struct tm *timeptr);
bool mktime( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [timeptrGuest] = *args;

    if (!timeptrGuest)
    {
        uint32_t ret{ static_cast<uint32_t>( -1 ) };
        if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write mktime return value" << std::endl;
            return false;
        }
        return true;
    }

    auto *tmGuest{ static_cast<guest::tm *>( timeptrGuest ) };
    struct tm tmHost{};
    tmHost.tm_sec = common::ensure_endianness( tmGuest->tm_sec, std::endian::big );
    tmHost.tm_min = common::ensure_endianness( tmGuest->tm_min, std::endian::big );
    tmHost.tm_hour = common::ensure_endianness( tmGuest->tm_hour, std::endian::big );
    tmHost.tm_mday = common::ensure_endianness( tmGuest->tm_mday, std::endian::big );
    tmHost.tm_mon = common::ensure_endianness( tmGuest->tm_mon, std::endian::big );
    tmHost.tm_year = common::ensure_endianness( tmGuest->tm_year, std::endian::big );
    tmHost.tm_wday = common::ensure_endianness( tmGuest->tm_wday, std::endian::big );
    tmHost.tm_yday = common::ensure_endianness( tmGuest->tm_yday, std::endian::big );
    tmHost.tm_isdst = common::ensure_endianness( tmGuest->tm_isdst, std::endian::big );

    time_t result{ ::mktime( &tmHost ) };
    uint32_t resultGuest{ static_cast<uint32_t>( result ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &resultGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write mktime return value" << std::endl;
        return false;
    }
    return true;
}

// void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
bool qsort( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, size_t, size_t, uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [base, nmemb, size, comparGuestPtr] = *args;

    if (!base || nmemb <= 1 || size == 0)
        return true;

    const uint32_t baseGuest{ mem->to_guest( base ) };
    auto *baseBytes{ static_cast<uint8_t *>( base ) };

    uc_context *ctx{};
    if (uc_context_alloc( uc, &ctx ) != UC_ERR_OK)
    {
        std::cerr << "qsort: uc_context_alloc failed" << std::endl;
        return false;
    }
    if (uc_context_save( uc, ctx ) != UC_ERR_OK)
    {
        std::cerr << "qsort: uc_context_save failed" << std::endl;
        uc_context_free( ctx );
        return false;
    }
    // Read SP from the saved context for comparator calls
    uint32_t sp{};
    uc_context_reg_read( ctx, UC_PPC_REG_1, &sp );

    // Sentinel: uc_emu_start stops when PC reaches this address (before executing / firing hooks)
    const uint32_t sentinel{ common::Inner_Emulation_Sentinel };

    std::vector<size_t> indices( nmemb );
    std::iota( indices.begin(), indices.end(), 0 );

    auto pred{ [&]( size_t i, size_t j ) {
        uint32_t ptrA{ baseGuest + static_cast<uint32_t>( i * size ) };
        uint32_t ptrB{ baseGuest + static_cast<uint32_t>( j * size ) };

        // Set up PPC state for comparator call
        uc_reg_write( uc, UC_PPC_REG_3, &ptrA ); // arg1 = pointer to element a
        uc_reg_write( uc, UC_PPC_REG_4, &ptrB ); // arg2 = pointer to element b
        uc_reg_write( uc, UC_PPC_REG_1, &sp );   // restore stack pointer
        uc_reg_write( uc, UC_PPC_REG_LR, &sentinel );

        uc_emu_start( uc, comparGuestPtr, sentinel, 0, 0 );

        uint32_t result{};
        uc_reg_read( uc, UC_PPC_REG_3, &result );
        return static_cast<int32_t>( result ) < 0;
    } };

    std::sort( indices.begin(), indices.end(), pred );

    std::vector<uint8_t> sorted( nmemb * size );
    for (std::size_t i{ 0 }; i < nmemb; i++)
        std::memcpy( sorted.data() + i * size, baseBytes + indices[i] * size, size );
    std::memcpy( baseBytes, sorted.data(), nmemb * size );

    uc_context_restore( uc, ctx );
    uc_context_free( ctx );

    return true;
}

// clock_t clock(void);
bool clock( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    clock_t ret{ ::clock() };
    uint32_t retGuest{ static_cast<uint32_t>( ret ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write clock return value" << std::endl;
        return false;
    }
    return true;
}

// char *setlocale(int category, const char *locale);
bool setlocale( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [category, locale] = *args;

    char *ret{ ::setlocale( category, locale ) };
    uint32_t retGuest{ 0 };

    if (ret != nullptr)
    {
        size_t len{ ::strlen( ret ) + 1 };
        void *localeHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( len ) ) ) };
        ::memcpy( localeHost, ret, len );
        retGuest = mem->to_guest( localeHost );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write setlocale return value" << std::endl;
        return false;
    }
    return true;
}

// int snprintf(char *str, size_t size, const char *format, ...);
bool snprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, size_t, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, size, format] = *args;

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_6, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsnprintf( str, size, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write snprintf return value" << std::endl;
        return false;
    }
    return true;
}

// char *strncat(char *dest, const char *src, size_t n);
bool strncat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, src, n] = *args;

    char *ret{ ::strncat( dest, src, n ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncat return value" << std::endl;
        return false;
    }
    return true;
}

// void *bsearch(const void *key, const void *base, size_t num, size_t width, int (*compare)(const void *, const void
// *))
bool bsearch( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, void *, std::size_t, std::size_t, uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [key, base, num, width, comparGuestPtr] = *args;

    if (!key || !base || num == 0 || width == 0)
    {
        uint32_t result{ 0 };
        if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
        {
            std::cerr << "Could not write bsearch return value" << std::endl;
            return false;
        }
        return true;
    }

    const uint32_t keyGuest{ mem->to_guest( const_cast<void *>( key ) ) };
    const uint32_t baseGuest{ mem->to_guest( const_cast<void *>( base ) ) };

    uc_context *ctx{};
    if (uc_context_alloc( uc, &ctx ) != UC_ERR_OK)
    {
        std::cerr << "bsearch: uc_context_alloc failed" << std::endl;
        return false;
    }
    if (uc_context_save( uc, ctx ) != UC_ERR_OK)
    {
        std::cerr << "bsearch: uc_context_save failed" << std::endl;
        uc_context_free( ctx );
        return false;
    }

    uint32_t sp{};
    uc_context_reg_read( ctx, UC_PPC_REG_1, &sp );

    const uint32_t sentinel{ common::Inner_Emulation_Sentinel };

    size_t left{ 0 };
    size_t right{ num };
    uint32_t resultGuest{ 0 }; // NULL — not found

    while (left < right)
    {
        size_t mid{ left + ( right - left ) / 2 };
        uint32_t midElemGuest{ baseGuest + static_cast<uint32_t>( mid * width ) };

        // Call guest comparator(key, &array[mid])
        uc_reg_write( uc, UC_PPC_REG_3, &keyGuest );
        uc_reg_write( uc, UC_PPC_REG_4, &midElemGuest );
        uc_reg_write( uc, UC_PPC_REG_1, &sp );
        uc_reg_write( uc, UC_PPC_REG_LR, &sentinel );

        uc_emu_start( uc, comparGuestPtr, sentinel, 0, 0 );

        uint32_t cmpRaw{};
        uc_reg_read( uc, UC_PPC_REG_3, &cmpRaw );
        const int32_t cmp{ static_cast<int32_t>( cmpRaw ) };

        if (cmp == 0)
        {
            resultGuest = midElemGuest;
            break;
        }
        else if (cmp < 0)
        {
            right = mid;
        }
        else
        {
            left = mid + 1;
        }
    }

    uc_context_restore( uc, ctx );
    uc_context_free( ctx );

    if (uc_reg_write( uc, UC_PPC_REG_3, &resultGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write bsearch return value" << std::endl;
        return false;
    }
    return true;
}

// double strtod(const char *str, char **endptr);
// Converts string to double
bool strtod( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, std::uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, endptr] = *args;

    char *hostEndPtr{ nullptr };
    double ret{ ::strtod( str, &hostEndPtr ) };

    if (endptr != 0 && hostEndPtr != nullptr)
    {
        std::uint32_t guestEndPtr{ common::ensure_endianness( mem->to_guest( hostEndPtr ), std::endian::big ) };

        std::uint32_t *endptrHost{ reinterpret_cast<std::uint32_t *>( mem->to_host( endptr ) ) };
        *endptrHost = guestEndPtr;
    }

    // Return double in FPR1 (PPC calling convention for floating point return values)
    if (uc_reg_write( uc, UC_PPC_REG_FPR1, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strtod return value" << std::endl;
        return false;
    }
    return true;
}

// long strtol(const char *str, char **endptr, int base);
// Converts string to long integer
bool strtol( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, std::uint32_t, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, endptr, base] = *args;

    char *hostEndPtr{ nullptr };
    long ret{ ::strtol( str, &hostEndPtr, base ) };

    if (endptr != 0 && hostEndPtr != nullptr)
    {
        std::uint32_t guestEndPtr{ common::ensure_endianness( mem->to_guest( hostEndPtr ), std::endian::big ) };

        std::uint32_t *endptrHost{ reinterpret_cast<std::uint32_t *>( mem->to_host( endptr ) ) };
        *endptrHost = guestEndPtr;
    }
    std::uint32_t retVal{ static_cast<std::uint32_t>( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retVal ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strtol return value" << std::endl;
        return false;
    }
    return true;
}
} // namespace import::callback