OsxPpcEmu

Project was instantiated to emulate some old PowerPC32 command line OSX programs.
Linking is based on dyld 46.16 (from Mac OS X 10.4.11).

# Quick Start Guide

## Choose Your Debugger Mode

### Interactive Debugger (Default)

```bash
./OsxPpcEmu <binary>
```

**When to use**: Quick debugging, command-line workflow, simple tasks

### IDA Pro Integration

```bash
GDB_SERVER=1 ./OsxPpcEmu <binary>
```

Then connect from IDA Pro: `Debugger → Attach → localhost:23946`

**When to use**: Complex analysis, visual debugging, reverse engineering

---

## Interactive Debugger Commands

| Command          | Description          | Example      |
|------------------|----------------------|--------------|
| `c`              | Continue execution   | `c`          |
| `s` or `si`      | Step one instruction | `s`          |
| `so`             | Step out of function | `so`         |
| `b <addr>`       | Set breakpoint       | `b 3620`     |
| `d <addr>`       | Delete breakpoint    | `d 3620`     |
| `l`              | List breakpoints     | `l`          |
| `r`              | Show registers       | `r`          |
| `bt`             | Show call stack      | `bt`         |
| `x <addr> <len>` | Hexdump memory       | `x 1000 100` |
| `h` or `?`       | Show help            | `h`          |
| `q`              | Quit                 | `q`          |

**Note**: Addresses are in hexadecimal (no 0x prefix needed)

---

## IDA Pro Quick Keys

| Key      | Action                |
|----------|-----------------------|
| `F7`     | Step Into             |
| `F8`     | Step Over             |
| `F9`     | Continue              |
| `F2`     | Set/Remove Breakpoint |
| `Ctrl+S` | Segments view         |
| `Alt+T`  | Stack view            |

---

## Common Workflows

### 1. Quick API Flow Check

```bash
./OsxPpcEmu myapp
(dbg) c
# Watch console for API calls
```

### 2. Debug Specific Function

```bash
./OsxPpcEmu myapp
(dbg) b 3700    # Function address
(dbg) c         # Run to breakpoint
(dbg) r         # Check registers
(dbg) s         # Step through
```

### 3. IDA Pro Analysis

```bash
GDB_SERVER=1 ./OsxPpcEmu myapp
# In IDA Pro:
# 1. Debugger → Attach → localhost:23946
# 2. Set breakpoints (F2)
# 3. Step through code (F7/F8)
```

---

## Tips

✅ **API tracing works in both modes** - Check the emulator console
✅ **Addresses are hex** - No 0x prefix in interactive mode
✅ **Use bt command** - Shows call stack with symbols
✅ **GDB Server mode** - Better for complex reverse engineering
✅ **Interactive mode** - Better for quick tests

---

## Environment Variables

| Variable     | Value        | Effect                   |
|--------------|--------------|--------------------------|
| `GDB_SERVER` | `1`          | Enable IDA Pro mode      |
| `GDB_SERVER` | `0` or unset | Use interactive debugger |

---

## Troubleshooting

**Problem**: Commands not working
**Fix**: Make sure you're in the right mode (check startup message)

**Problem**: IDA Pro won't connect
**Fix**:

```bash
echo $GDB_SERVER  # Should show "1"
netstat -an | grep 23946  # Should show LISTEN
```

**Problem**: Step commands hang in IDA
**Fix**: Rebuild project after latest updates

---

## Example Session

```bash
$ ./OsxPpcEmu samples/mwpefcc

=== Interactive Debugger ===
Entry point: 0x3610

(dbg) b 3700
Breakpoint added at 0x3700

(dbg) c
Continuing...
┌─ _printf <- _main
│  arg0: 0x1234 ("Hello")
└─ return: 0x5

=== Breakpoint at 0x3700 ===
(dbg) r
PC  = 0x00003700
LR  = 0x00003650
R3  = 0x00001234
...

(dbg) bt
Call stack:
  #0  0x00003700 <_myfunction>
  #1  0x00003650 <_main>
  #2  0x000036a0 <__start>

(dbg) s
(dbg) s
(dbg) c
```

---

# Dyld notes

Almost each executable in Darwin (OSX) is linked dynamically, that means all needed functions are linked during binary
load.
On Mac OS X (10.4) when MachO is executed, kernel (xnu/bsd/kern/mach_loader.c):

- maps segments (LC_COMMAND),
- sets entry point (LC_UNIXTHREAD)
- load dynamic linker (pointed by LC_LOAD_DYLINKER) and let it do the rest of the job (in userland)
  MachO executables (MH_EXECUTE) does not need to relocated.

Then kernel redirects execution to __dyld_start (dyldStartup.s) (each arch has its own asm snippet). It takes care of:

- mapping and relocating dynamic libraries (MH_DYLIB) recursively (LC_LOAD_DYLIB, LC_DYSYMTAB)
- calling init functions from libraries (LC_ROUTINES)

Then redirects execution to loaded MachO executable entry point.

Imported symbols pointers are in

- __nl_symbol_ptr section (non lazy symbols)
- __la_symbol_ptr section (lazy symbols)

![non lazy symbols view in IDA Pro](img/nl_ida.png "Non Lazy view")
For non lazy symbols, dyld loads them during load so when executable is loaded, all pointers are filled with actual
adresses (function/pointers etc.)

![resolved non lazy symbol ptr in gdb view](img/nl_gdb.png)
As it turns out these 3 symbols addresses are pointers in DATA segment in libsystem.B.dylib (checked using vmmap).

![lazy symbols view in IDA Pro](img/la_ida.png "Lazy view")
For lazy symbols, dyld loads them during runtime when first call is encountered.

![lazy symbol stub](img/la_gdb.png)
3 lazy symbols at 0x2020 points to the same address (in main executable TEXT segment).
That's the dyld_stub_binding_helper that calls _stub_binding_helper in dyld (0x8FE01000, address is hardcoded in
binary (no ASLR at that time yet), that's the specific address for dyld)
and it leads to call uintptr_t dyld::bindLazySymbol(const mach_header* mh, uintptr_t* lazyPointer)

dyld parses LC_LOAD_DYLIB load command to get to know which dylib load
then it uses info from LC_DYSYMTAB.

- Local Symbols (index in LC_SYMTAB and count of local symbols in the symbol table LC_SYMTAB)
- External Defined Symbols (index in LC_SYMTAB and count of symbols that are exported, i.e. other dylibs/executables can
  link against them)
- Undefined External Symbols (index in LC_SYMTAB and count of symbols that needs to be imported from other
  binaries/dylibs)
- Table of Contents (offset in file and count, used in archive libraries (.a) only)
- Module Table (offset in file and count, used in static libraries to group symbols by object file, 0 for normal
  executables)
- External Reference Symbols (offset in file and count, used in archives/static linking)
- Indirect Symbol Table (offset in file to indirect symbol table and how many entries it has)
  When you call a function from another dylib, your code doesn't call it directly, it calls a stub that jumps through
  and indirect symbol table entry
- External Relocation Entries (offset and count, often 0 because dyld handles binding through stubs instead)
- Local Relocation Entries (offset and count, used for relocations that apply only within local/launched executable)

### References:

- MacOS and iOS Internals, Volume 1 User Mode, Jonathan Levin
- Mac OS X Internals: A Systems Approach, Amit Singh