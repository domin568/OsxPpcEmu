/**
 * Author:    domin568
 * Created:   16.05.2026
 * Brief:     redirected API implementations
 **/

#include "COsxPpcEmu.hpp"
#include "ImportDispatch.hpp"
#include "PpcStructures.hpp"
#include "shims/ShimContext.hpp"
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
bool PBGetCatInfoSync( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *>() };
    if (!args.has_value())
        return false;
    const auto [paramBlock] = *args;

    return ctx.ret( -1 );
}

// OSErr FSpOpenRF(const FSSpec *spec, SInt8 permission, SInt16 *refNum)
// Opens the resource fork of a file
bool FSpOpenRF( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const void *, std::int8_t, std::int16_t *>() };
    if (!args.has_value())
        return false;
    const auto [spec, permission, refNumPtr] = *args;

    return ctx.ret( 0 );
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
bool FSpOpenResFile( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const std::uint8_t *, std::int8_t>() };
    if (!args.has_value())
        return false;
    const auto [specPtr, permission] = *args;

    auto write_short_result{ [ctx]( std::int32_t r ) -> bool {
        std::int32_t v{ r };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &v ) != UC_ERR_OK)
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
    const std::string rsrcPath{ fullPath +
                                "_rsrc" }; // you need to extract resource forks for app to make it cross platform

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
    const auto rd16{
        []( const std::uint8_t *p ) -> std::uint16_t { return static_cast<std::uint16_t>( ( p[0] << 8 ) | p[1] ); } };
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
bool Get1Resource( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t, std::int16_t>() };
    if (!args.has_value())
        return false;
    const auto [resType, resID] = *args;

    auto write_handle{ [ctx]( std::uint32_t h ) -> bool {
        std::uint32_t v{ h };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &v ) != UC_ERR_OK)
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
    const std::uint32_t handle{ load_one_resource( ctx.mem, fdIt->second, resType, resID, dataVa, size ) };
    if (handle == 0)
        return write_handle( 0 );

    g_loadedResources[handle] = LoadedResource{ g_currentResFile, handle, dataVa, size, resType, resID, false };

    return write_handle( handle );
}

// void DetachResource(Handle theResource)
// Disconnects `theResource` from the Resource Manager so the caller becomes
// responsible for disposing of the handle.  After this call, CloseResFile
// will not free the handle's storage.
bool DetachResource( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
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
bool CloseResFile( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::int16_t>() };
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
    const std::uint32_t parID{
        common::ensure_endianness( *reinterpret_cast<const std::uint32_t *>( specPtr + 2 ), std::endian::big ) };
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
bool FSpGetFInfo( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const std::uint8_t *, std::uint8_t *>() };
    if (!args.has_value())
        return false;
    const auto [specPtr, fndrInfoPtr] = *args;

    auto write_result{ [ctx]( std::int32_t r ) -> bool {
        std::int32_t v{ r };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &v ) != UC_ERR_OK)
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

    return ctx.ret( 0 );
}

// OSErr FSpSetFInfo(const FSSpec *spec, const FInfo *fndrInfo)
bool FSpSetFInfo( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const std::uint8_t *, const std::uint8_t *>() };
    if (!args.has_value())
        return false;
    const auto [specPtr, fndrInfoPtr] = *args;

    auto write_result{ [ctx]( std::int32_t r ) -> bool {
        std::int32_t v{ r };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &v ) != UC_ERR_OK)
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
    if (::setxattr( hostPath.c_str(), "com.apple.FinderInfo", finderInfo, sizeof( finderInfo ), 0, XATTR_NOFOLLOW ) !=
        0)
        return write_result( errno == EACCES || errno == EPERM ? wrPermErr : ioErr );
#endif

    return ctx.ret( 0 );
}

// OSErr FSWrite(SInt16 refNum, SInt32 *count, const void *buffPtr)
// Writes data to an open file
bool FSWrite( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::int16_t, std::int32_t *, const void *>() };
    if (!args.has_value())
        return false;
    const auto [refNum, countPtr, buffPtr] = *args;

    return ctx.ret( 0 );
}

// OSErr FSClose(SInt16 refNum)
// Closes an open file. If `refNum` was issued by FSpOpenResFile / FSpOpenRF
// we forward the close() to the underlying host fd.
bool FSClose( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::int16_t>() };
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

    return ctx.ret( 0 );
}

// void BlockMoveData(const void *srcPtr, void *destPtr, Size byteCount)
// CoreServices.framework/Frameworks/CarbonCore.framework/Headers/MacMemory.h
bool BlockMoveData( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, void *, std::uint32_t>() };
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
bool FSPathMakeRef( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, void *, std::uint8_t *>() };
    if (!args.has_value())
        return false;
    const auto [path, refPtr, isDirectoryPtr] = *args;

    // Carbon File Manager error codes
    constexpr std::int32_t noErr{ 0 };
    constexpr std::int32_t paramErr{ -50 };
    constexpr std::int32_t bdNamErr{ -37 };
    constexpr std::int32_t fnfErr{ -43 };

    auto write_result{ [ctx]( std::int32_t status ) -> bool {
        std::int32_t r{ status };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &r ) != UC_ERR_OK)
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

    return ctx.ret( noErr );
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
bool FSGetCatalogInfo( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const std::uint8_t *, std::uint32_t, std::uint8_t *, std::uint8_t *,
                                       std::uint8_t *, std::uint8_t *>() };
    if (!args.has_value())
        return false;
    const auto [refPtr, whichInfo, catInfoPtr, outNamePtr, fsSpecPtr, parentRefPtr] = *args;

    constexpr std::int32_t noErr{ 0 };
    constexpr std::int32_t paramErr{ -50 };
    constexpr std::int32_t fnfErr{ -43 };
    constexpr std::int32_t nsvErr{ -35 };

    auto write_result{ [ctx]( std::int32_t status ) -> bool {
        std::int32_t r{ status };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &r ) != UC_ERR_OK)
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

    return ctx.ret( noErr );
}
// Handle TempNewHandle(Size logicalSize, OSErr* resultCode)
// Allocate a relocatable memory block of a specified size.
bool TempNewHandle( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [logicalSize] = *args;

    const std::uint32_t alloc{ ctx.mem->heap_alloc( logicalSize ) };
    std::uint32_t *ptrHost{
        reinterpret_cast<std::uint32_t *>( ctx.mem->to_host( ctx.mem->heap_alloc( sizeof( std::uint32_t ) ) ) ) };
    *ptrHost = common::ensure_endianness( alloc, std::endian::big );
    std::uint32_t ptrGuest{ ctx.mem->to_guest( ptrHost ) };

    g_lastMemError = ( alloc == 0 ) ? memFullErr : noErr;

    return ctx.ret( ptrGuest );
}

// Size GetHandleSize(Handle h)
// Returns the size of the allocated memory block referenced by a handle.
bool GetHandleSize( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [handleGuest] = *args;

    std::uint32_t size{ 0 };
    if (handleGuest != 0)
    {
        const std::uint32_t *handleHost{ reinterpret_cast<const std::uint32_t *>( ctx.mem->get( handleGuest ) ) };
        if (handleHost != nullptr)
        {
            const std::uint32_t ptrGuest{ common::ensure_endianness( *handleHost, std::endian::big ) };
            size = static_cast<std::uint32_t>( ctx.mem->get_alloc_size( ptrGuest ) );
        }
    }

    return ctx.ret( size );
}

// void DisposeHandle(Handle h)
// Releases the memory occupied by a relocatable block.
bool DisposeHandle( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
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
bool HandAndHand( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t, std::uint32_t>() };
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
        std::uint32_t *handle1Host{ reinterpret_cast<std::uint32_t *>( ctx.mem->get( hand1Guest ) ) };
        std::uint32_t *handle2Host{ reinterpret_cast<std::uint32_t *>( ctx.mem->get( hand2Guest ) ) };

        if (handle1Host == nullptr || handle2Host == nullptr)
        {
            result = memFullErr;
            g_lastMemError = memFullErr;
        }
        else
        {
            const std::uint32_t ptr1Guest{ common::ensure_endianness( *handle1Host, std::endian::big ) };
            const std::uint32_t ptr2Guest{ common::ensure_endianness( *handle2Host, std::endian::big ) };

            const std::size_t size1{ ctx.mem->get_alloc_size( ptr1Guest ) };
            const std::size_t size2{ ctx.mem->get_alloc_size( ptr2Guest ) };

            const std::size_t newSize{ size2 + size1 };

            const std::uint32_t newAlloc{ ctx.mem->heap_alloc( newSize ) };
            if (newAlloc == 0)
            {
                result = memFullErr;
                g_lastMemError = memFullErr;
            }
            else
            {
                void *ptr1{ ctx.mem->get( ptr1Guest ) };
                void *ptr2{ ctx.mem->get( ptr2Guest ) };
                void *newPtr{ ctx.mem->get( newAlloc ) };

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

    return ctx.ret( result );
}

// void HLock(Handle h)
// Locks a relocatable block so it cannot be moved during heap compaction.
bool HLock( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
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
bool HLockHi( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
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
bool HUnlock( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
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
bool MemError( ShimContext &ctx )
{
    std::uint32_t err{ static_cast<std::uint32_t>( g_lastMemError ) };

    return ctx.ret( err );
}

// Handle NewHandle(Size logicalSize)
// Allocate a relocatable memory block of a specified size.
bool NewHandle( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [logicalSize] = *args;

    const std::uint32_t alloc{ ctx.mem->heap_alloc( logicalSize ) };
    std::uint32_t *ptrHost{
        reinterpret_cast<std::uint32_t *>( ctx.mem->to_host( ctx.mem->heap_alloc( sizeof( std::uint32_t ) ) ) ) };
    *ptrHost = common::ensure_endianness( alloc, std::endian::big );
    std::uint32_t ptrGuest{ ctx.mem->to_guest( ptrHost ) };

    // Set memory error status
    g_lastMemError = ( alloc == 0 ) ? memFullErr : noErr;

    return ctx.ret( ptrGuest );
}

// Handle NewHandleClear(Size logicalSize)
// Allocate a relocatable memory block and clear it to zeros.
bool NewHandleClear( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [logicalSize] = *args;

    const std::uint32_t alloc{ ctx.mem->heap_alloc( logicalSize ) };

    // Clear the allocated memory
    void *allocPtr{ ctx.mem->get( alloc ) };
    if (allocPtr)
    {
        ::memset( allocPtr, 0, logicalSize );
    }

    std::uint32_t *ptrHost{
        reinterpret_cast<std::uint32_t *>( ctx.mem->to_host( ctx.mem->heap_alloc( sizeof( std::uint32_t ) ) ) ) };
    *ptrHost = common::ensure_endianness( alloc, std::endian::big );
    std::uint32_t ptrGuest{ ctx.mem->to_guest( ptrHost ) };

    // Set memory error status
    g_lastMemError = ( alloc == 0 ) ? memFullErr : noErr;

    return ctx.ret( ptrGuest );
}

// OSErr PtrAndHand(const void *ptr1, Handle hand2, long size)
// Concatenates part or all of a memory block to the end of a relocatable block.
bool PtrAndHand( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const void *, std::uint32_t, std::int32_t>() };
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
        std::uint32_t *handleHost{ reinterpret_cast<std::uint32_t *>( ctx.mem->get( hand2Guest ) ) };
        if (handleHost == nullptr)
        {
            result = memFullErr;
            g_lastMemError = memFullErr;
        }
        else
        {
            // Read the pointer value (big-endian) that the handle points to
            const std::uint32_t oldPtrGuest{ common::ensure_endianness( *handleHost, std::endian::big ) };
            const std::size_t oldSize{ ctx.mem->get_alloc_size( oldPtrGuest ) };

            // Calculate new size
            const std::size_t newSize{ oldSize + static_cast<std::size_t>( size ) };

            // Allocate new memory block
            const std::uint32_t newAlloc{ ctx.mem->heap_alloc( newSize ) };

            if (newAlloc == 0)
            {
                result = memFullErr;
                g_lastMemError = memFullErr;
            }
            else
            {
                // Copy old data to new location
                void *oldPtr{ ctx.mem->get( oldPtrGuest ) };
                void *newPtr{ ctx.mem->get( newAlloc ) };
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

    return ctx.ret( result );
}

// void SetHandleSize(Handle h, Size newSize)
// Changes the logical size of the relocatable block associated with a handle.
bool SetHandleSize( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t, std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [handleGuest, newSize] = *args;

    if (handleGuest == 0)
    {
        g_lastMemError = memFullErr;
        return true;
    }

    // Handle is a pointer to a pointer - get the handle's host address
    std::uint32_t *handleHost{ reinterpret_cast<std::uint32_t *>( ctx.mem->get( handleGuest ) ) };
    if (handleHost == nullptr)
    {
        g_lastMemError = memFullErr;
        return true;
    }

    // Read the pointer value (big-endian) that the handle points to
    const std::uint32_t oldPtrGuest{ common::ensure_endianness( *handleHost, std::endian::big ) };
    const std::size_t oldSize{ ctx.mem->get_alloc_size( oldPtrGuest ) };

    if (newSize <= oldSize)
    {
        // Shrinking or same size - just update the tracked size
        ctx.mem->set_alloc_size( oldPtrGuest, newSize );
        g_lastMemError = noErr;
    }
    else
    {
        // Growing - need to allocate new memory and copy old data
        const std::uint32_t newAlloc{ ctx.mem->heap_alloc( newSize ) };

        if (newAlloc == 0)
        {
            g_lastMemError = memFullErr;
        }
        else
        {
            // Copy old data to new location
            void *oldPtr{ ctx.mem->get( oldPtrGuest ) };
            void *newPtr{ ctx.mem->get( newAlloc ) };
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
} // namespace import::callback
