use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::{env, io};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(non_snake_case)]
struct DosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

fn read_dos_header(file: &mut File) -> std::io::Result<DosHeader> {
    let e_magic = file.read_u16::<LittleEndian>()?;
    if e_magic != 0x5A4D {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid DOS header signature",
        ));
    }

    Ok(DosHeader {
        e_magic,
        e_cblp: file.read_u16::<LittleEndian>()?,
        e_cp: file.read_u16::<LittleEndian>()?,
        e_crlc: file.read_u16::<LittleEndian>()?,
        e_cparhdr: file.read_u16::<LittleEndian>()?,
        e_minalloc: file.read_u16::<LittleEndian>()?,
        e_maxalloc: file.read_u16::<LittleEndian>()?,
        e_ss: file.read_u16::<LittleEndian>()?,
        e_sp: file.read_u16::<LittleEndian>()?,
        e_csum: file.read_u16::<LittleEndian>()?,
        e_ip: file.read_u16::<LittleEndian>()?,
        e_cs: file.read_u16::<LittleEndian>()?,
        e_lfarlc: file.read_u16::<LittleEndian>()?,
        e_ovno: file.read_u16::<LittleEndian>()?,
        e_res: [
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
        ],
        e_oemid: file.read_u16::<LittleEndian>()?,
        e_oeminfo: file.read_u16::<LittleEndian>()?,
        e_res2: [
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
            file.read_u16::<LittleEndian>()?,
        ],
        e_lfanew: file.read_i32::<LittleEndian>()?,
    })
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(non_snake_case)]
struct PeHeader {
    Signature: u32,
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(non_snake_case)]
struct ImageDataDirectory {
    VirtualAddress: u32,
    Size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(non_snake_case)]
struct OptionalHeader {
    Magic: u16,
    MajorLinkVersion: u8,
    MinorLinkVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [ImageDataDirectory; 16],
}

fn read_optional_header(file: &mut File) -> std::io::Result<OptionalHeader> {
    let mut output = OptionalHeader {
        Magic: file.read_u16::<LittleEndian>()?,
        MajorLinkVersion: file.read_u8()?,
        MinorLinkVersion: file.read_u8()?,
        SizeOfCode: file.read_u32::<LittleEndian>()?,
        SizeOfInitializedData: file.read_u32::<LittleEndian>()?,
        SizeOfUninitializedData: file.read_u32::<LittleEndian>()?,
        AddressOfEntryPoint: file.read_u32::<LittleEndian>()?,
        BaseOfCode: file.read_u32::<LittleEndian>()?,
        ImageBase: file.read_u64::<LittleEndian>()?,
        SectionAlignment: file.read_u32::<LittleEndian>()?,
        FileAlignment: file.read_u32::<LittleEndian>()?,
        MajorOperatingSystemVersion: file.read_u16::<LittleEndian>()?,
        MinorOperatingSystemVersion: file.read_u16::<LittleEndian>()?,
        MajorImageVersion: file.read_u16::<LittleEndian>()?,
        MinorImageVersion: file.read_u16::<LittleEndian>()?,
        MajorSubsystemVersion: file.read_u16::<LittleEndian>()?,
        MinorSubsystemVersion: file.read_u16::<LittleEndian>()?,
        Win32VersionValue: file.read_u32::<LittleEndian>()?,
        SizeOfImage: file.read_u32::<LittleEndian>()?,
        SizeOfHeaders: file.read_u32::<LittleEndian>()?,
        CheckSum: file.read_u32::<LittleEndian>()?,
        Subsystem: file.read_u16::<LittleEndian>()?,
        DllCharacteristics: file.read_u16::<LittleEndian>()?,
        SizeOfStackReserve: file.read_u64::<LittleEndian>()?,
        SizeOfStackCommit: file.read_u64::<LittleEndian>()?,
        SizeOfHeapReserve: file.read_u64::<LittleEndian>()?,
        SizeOfHeapCommit: file.read_u64::<LittleEndian>()?,
        LoaderFlags: file.read_u32::<LittleEndian>()?,
        NumberOfRvaAndSizes: file.read_u32::<LittleEndian>()?,
        DataDirectory: [ImageDataDirectory {
            VirtualAddress: 0,
            Size: 0,
        }; 16],
    };

    for i in 0..16 {
        output.DataDirectory[i] = ImageDataDirectory {
            VirtualAddress: file.read_u32::<LittleEndian>()?,
            Size: file.read_u32::<LittleEndian>()?,
        };
    }

    Ok(output)
}

// Technically it should be like:
// DOS_HEADER
// NT_HEADER { FILE_HEADER, OPTIONAL_HEADER }

fn read_pe_header(file: &mut File, offset: u64) -> std::io::Result<PeHeader> {
    file.seek(SeekFrom::Start(offset))?;

    let signature = file.read_u32::<LittleEndian>()?;
    if signature != 0x00004550 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid PE header signature",
        ));
    }

    Ok(PeHeader {
        Signature: signature,
        Machine: file.read_u16::<LittleEndian>()?,
        NumberOfSections: file.read_u16::<LittleEndian>()?,
        TimeDateStamp: file.read_u32::<LittleEndian>()?,
        PointerToSymbolTable: file.read_u32::<LittleEndian>()?,
        NumberOfSymbols: file.read_u32::<LittleEndian>()?,
        SizeOfOptionalHeader: file.read_u16::<LittleEndian>()?,
        Characteristics: file.read_u16::<LittleEndian>()?,
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("[Usage] portable_rustable.exe <path_to_file>");
        return;
    }

    let path_to_file = Path::new(&args[1]);
    if !path_to_file.exists() {
        println!("[Error] File does not exist");
        return;
    }

    let mut file = File::open(path_to_file).unwrap();

    match read_dos_header(&mut file) {
        Ok(dos_header) => {
            println!("DOS_HEADER: {:#x?}", dos_header);

            let pe_header_offset = dos_header.e_lfanew;
            match read_pe_header(&mut file, pe_header_offset.try_into().unwrap()) {
                Ok(pe_header) => {
                    println!("PE_HEADER: {:#x?}", pe_header);

                    // read optional header
                }
                Err(e) => eprintln!("ERROR: {}", e),
            }
        }
        Err(e) => eprintln!("ERROR: {}", e),
    }
}
