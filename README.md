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
    e_lfanew: 0x118,
}
PE_HEADER: PeHeader {
    Signature: 0x4550,
    Machine: 0x14c,
    NumberOfSections: 0x7,
    TimeDateStamp: 0x5a2f1c6a,
    PointerToSymbolTable: 0x0,
    NumberOfSymbols: 0x0,
    SizeOfOptionalHeader: 0xe0,
    Characteristics: 0x122,
}
IMAGE_OPTIONAL_HEADER: OptionalHeader {
    Magic: 0x10b,
    MajorLinkVersion: 0xe,
    MinorLinkVersion: 0x0,
    SizeOfCode: 0x52e00,
    SizeOfInitializedData: 0xaa800,
    SizeOfUninitializedData: 0x0,
    AddressOfEntryPoint: 0x38430,
    BaseOfCode: 0x1000,
    ImageBase: 0x40000000054000,
    SectionAlignment: 0x1000,
    FileAlignment: 0x200,
    MajorOperatingSystemVersion: 0x5,
    MinorOperatingSystemVersion: 0x1,
    MajorImageVersion: 0x0,
    MinorImageVersion: 0x0,
    MajorSubsystemVersion: 0x5,
    MinorSubsystemVersion: 0x1,
    Win32VersionValue: 0x0,
    SizeOfImage: 0x102000,
    SizeOfHeaders: 0x400,
    CheckSum: 0xfd6fc,
    Subsystem: 0x2,
    DllCharacteristics: 0x8140,
    SizeOfStackReserve: 0x100000180000,
    SizeOfStackCommit: 0x100000100000,
    SizeOfHeapReserve: 0x1000000000,
    SizeOfHeapCommit: 0x800006ee20,
    LoaderFlags: 0x6eea0,
    NumberOfRvaAndSizes: 0x3c,
    DataDirectory: [
        ImageDataDirectory {
            VirtualAddress: 0x78000,
            Size: 0x83590,
        },
        ImageDataDirectory {
            VirtualAddress: 0x0,
            Size: 0x0,
        },
        ImageDataDirectory {
            VirtualAddress: 0xfba00,
            Size: 0x1b20,
        },
        ImageDataDirectory {
            VirtualAddress: 0xfc000,
            Size: 0x5798,
        },
        ImageDataDirectory {
            VirtualAddress: 0x662f0,
            Size: 0x70,
        },
        ImageDataDirectory {
            VirtualAddress: 0x0,
            Size: 0x0,
        },
        ImageDataDirectory {
            VirtualAddress: 0x0,
            Size: 0x0,
        },
        ImageDataDirectory {
            VirtualAddress: 0x663bc,
            Size: 0x18,
        },
        ImageDataDirectory {
            VirtualAddress: 0x66360,
            Size: 0x40,
        },
        ImageDataDirectory {
            VirtualAddress: 0x0,
            Size: 0x0,
        },
        ImageDataDirectory {
            VirtualAddress: 0x54000,
            Size: 0x18c,
        },
        ImageDataDirectory {
            VirtualAddress: 0x0,
            Size: 0x0,
        },
        ImageDataDirectory {
            VirtualAddress: 0x0,
            Size: 0x0,
        },
        ImageDataDirectory {
            VirtualAddress: 0x0,
            Size: 0x0,
        },
        ImageDataDirectory {
            VirtualAddress: 0x7865742e,
            Size: 0x74,
        },
        ImageDataDirectory {
            VirtualAddress: 0x52dbd,
            Size: 0x1000,
        },
    ],
}
```
## TODO:
- Read Optional Header
- Read sections
- Read imports/exports
- Read strings
- Read hash md5/sha1
- (maybe) add gui
