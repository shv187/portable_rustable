use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::{env, io};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
