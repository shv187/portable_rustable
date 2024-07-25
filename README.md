# portable_rustable
## Usage:
`rustable_executable.exe <file_path>`
## Example of output:
```
DOS_HEADER: DosHeader {
    e_magic: 0x5a4d,
    e_cblp: 0x90,
    e_cp: 0x3,
    e_crlc: 0x0,
    e_cparhdr: 0x4,
    e_minalloc: 0x0,
    e_maxalloc: 0xffff,
    e_ss: 0x0,
    e_sp: 0xb8,
    e_csum: 0x0,
    e_ip: 0x0,
    e_cs: 0x0,
    e_lfarlc: 0x40,
    e_ovno: 0x0,
    e_res: [
        0x0,
        0x0,
        0x0,
        0x0,
    ],
    e_oemid: 0x0,
    e_oeminfo: 0x0,
    e_res2: [
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
    ],
    e_lfanew: 0xf8,
}
PE_HEADER: PeHeader {
    Signature: 0x4550,
    Machine: 0x14c,
    NumberOfSections: 0x9,
    TimeDateStamp: 0x66a274ed,
    PointerToSymbolTable: 0x0,
    NumberOfSymbols: 0x0,
    SizeOfOptionalHeader: 0xe0,
    Characteristics: 0x2102,
}
```
## TODO:
- Read Optional Header
- Read sections
- Read imports/exports
- Read strings
- Read hash md5/sha1
- (maybe) add gui
