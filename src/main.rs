use byteparse::*;
use std::io::{self, Read, BufRead, Write, Seek};
use std::cell::RefCell;
use std::mem;

mod pe;

pub trait PeSource: BufRead + Seek {}
impl<T: BufRead + Seek> PeSource for T {}

pub enum ExportAddr {
    Rva(u64),
    Forwarded((String, String))
}

pub enum ImportFunc {
    ByName(String),
    ByOrd(u16)
}

pub struct Export {
    pub name: Option<String>,
    pub addr: ExportAddr,
    pub ord:  u16
}

pub struct Import {
    pub name:  String,
    pub funcs: Vec<ImportFunc>
}

pub struct Section {
    pub name:      String,
    pub virt_addr: u32,
    pub virt_len:  u32,
    pub raw_addr:  u32,
    pub raw_len:   u32,
    pub flags:     u32
}

pub struct PortableExecutable {
    dos:     pe::ImageDosHeader,
    nt:      pe::ImageNtHeaders64,
    secs:    Vec<Section>,
    exports: Vec<Export>,
    imports: Vec<Import>
}

impl PortableExecutable {
    pub fn parse<T: PeSource>(source: T) -> io::Result<PortableExecutable> {
        PortableExecutableParser::parse(source)
    }

    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    pub fn exports(&self) -> &[Export] {
        &self.exports
    }

    pub fn sections(&self) -> &[Section] {
        &self.secs
    }

    pub fn nt_header(&self) -> &pe::ImageNtHeaders64 {
        &self.nt
    }

    pub fn dos_header(&self) -> &pe::ImageDosHeader {
        &self.dos
    }
}

struct PortableExecutableParser<T: PeSource> {
    source: RefCell<T>,
    p:      PortableExecutable
}

impl<T: PeSource> PortableExecutableParser<T> {
    fn parse(source: T) -> io::Result<PortableExecutable> {
        let p = PortableExecutable {
            dos:     Default::default(),
            nt:      Default::default(),
            secs:    Default::default(),
            exports: Default::default(),
            imports: Default::default()
        };

        let mut parser = Self {
            source: RefCell::new(source),
            p
        };

        parser.parse_self()?;
        Ok(parser.p)
    }

    fn parse_self(&mut self) -> io::Result<()> {
        self.p.dos = self.at(0)?;
        self.p.nt  = self.at(self.p.dos.e_lfanew as u64)?;

        assert_eq!(self.p.dos.e_magic,  u16::from_le_bytes(*b"MZ"));
        assert_eq!(self.p.nt.signature, u32::from_le_bytes(*b"PE\0\0"));

        self.load_sections()?;
        self.load_exports()?;
        self.load_imports()?;
        Ok(())
    }

    fn load_sections(&mut self) -> io::Result<()> {
        let sec_headers = self.p.dos.e_lfanew as u64 + 
            mem::size_of::<pe::ImageFileHeader>() as u64 +
            self.p.nt.file_header.size_of_optional_header as u64 + 4;

        for i in 0..(self.p.nt.file_header.number_of_sections as u64) {
            let sec = sec_headers +
                mem::size_of::<pe::ImageSectionHeader>() as u64 * i;
            let sec: pe::ImageSectionHeader = self.at(sec)?;
            let name: String = sec.name.iter() 
                .take_while(|v| **v != 0)
                .map(|v| *v as char)
                .collect();

            self.p.secs.push(Section {
                name,
                virt_addr: sec.virtual_address,
                virt_len:  sec.virtual_size,
                raw_addr:  sec.pointer_to_raw_data,
                raw_len:   sec.size_of_raw_data,
                flags:     sec.characteristics
            });
        }

        Ok(())
    }

    fn load_exports(&mut self) -> io::Result<()> {
        let dir     = self.p.nt.optional_header.data_directory[0];
        let dir_rva = dir.virtual_address as u64;
        let dir_len = dir.size            as u64;

        if dir_rva == 0 || dir_len == 0 {
            return Ok(());
        }

        let export: pe::ImageExportDirectory = self.at_rva(dir_rva)?;
        let names = export.address_of_names     as u64;
        let funcs = export.address_of_functions as u64;

        use std::hash::{Hash, Hasher};
        use fnv::FnvHashSet;

        struct OrdEntry(u64, u16);

        impl Hash for OrdEntry {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.1.hash(state);
            }
        }

        impl PartialEq for OrdEntry {
            fn eq(&self, o: &OrdEntry) -> bool {
                self.1 == o.1
            }
        }

        impl Eq for OrdEntry {}

        let name_ords: FnvHashSet<OrdEntry> = {
            let ords       = export.address_of_name_ordinals as u64;
            let mut source = self.source.borrow_mut();

            source.seek(std::io::SeekFrom::Start(self.conv_rva(ords as u64)))?;

            let mut buf = vec![0u8; (export.number_of_names * 2) as usize];
            source.read_exact(&mut buf)?;

            buf.chunks(2).enumerate()
                .map(|(i, v)| {
                    OrdEntry(i as u64, u16::from_le_bytes([v[0], v[1]]))
                })
                .collect()
        };
        
        for i in 0..(export.number_of_functions as u64) {
            let name_data = name_ords.get(&OrdEntry(0, i as u16));

            let name = if let Some(OrdEntry(ni, _)) = name_data {
                let name_rva: u32 = self.at_rva(names + ni * 4)?;
                Some(self.read_str(name_rva as u64)?)
            } else {
                None
            };
    
            let func: u32 = self.at_rva(funcs + i as u64 * 4)?;
            let func      = func as u64;
            let forwarded = func >= dir_rva && func < dir_rva + dir_len;

            let addr = if forwarded {
                let forwarder = self.read_str(func)?;
                let mut iter  = forwarder.splitn(2, '.');

                if let (Some(m), Some(f)) = (iter.next(), iter.next()) {
                    ExportAddr::Forwarded((m.to_owned() + ".dll",
                        f.to_owned()))
                } else {
                    ExportAddr::Forwarded((forwarder, "".to_owned()))
                }

            } else {
                ExportAddr::Rva(func)
            };

            self.p.exports.push(Export {
                name, 
                addr,
                ord: export.base as u16 + i as u16
            });
        }

        Ok(())
    }

    fn load_imports(&mut self) -> io::Result<()> {
        let dir     = self.p.nt.optional_header.data_directory[1];
        let dir_rva = dir.virtual_address as u64;
        let dir_len = dir.size            as u64;

        if dir_rva == 0 || dir_len == 0 {
            return Ok(());
        }

        let mut import_addr = dir_rva;
        loop {
            let import: pe::ImageImportDescriptor = self.at_rva(import_addr)?;
            if import.name == 0 {
                break;
            }
            import_addr += mem::size_of::<pe::ImageImportDescriptor>() as u64;

            let mut module = Import {
                name:  self.read_str(import.name as u64)?,
                funcs: Default::default()
            };

            let mut lookup_addr = if import.original_first_thunk == 0 {
                import.first_thunk as u64
            } else {
                import.original_first_thunk as u64
            };

            loop {
                let entry: u64 = self.at_rva(lookup_addr)?;
                if entry == 0 {
                    break;
                }
                lookup_addr += 8;

                module.funcs.push(if entry & 0x8000000000000000 != 0 {
                    ImportFunc::ByOrd(entry as u16)
                } else {
                    ImportFunc::ByName(self.read_str(entry + 2)?)
                });
            }

            self.p.imports.push(module);
        }

        Ok(())
    }

    fn conv_rva(&self, rva: u64) -> u64 {
        for sec in &self.p.secs {
            if rva >= sec.virt_addr as u64 && 
                rva < (sec.virt_addr + sec.virt_len) as u64 
            {
                return rva - sec.virt_addr as u64 + sec.raw_addr as u64;
            }
        }

        rva
    }

    fn read_str(&self, rva: u64) -> io::Result<String> {
        let rva = self.conv_rva(rva);

        let mut source = self.source.borrow_mut();
        let mut buf    = Vec::new();
        
        source.seek(std::io::SeekFrom::Start(rva as u64))?;
        source.read_until(0, &mut buf)?;

        let cutoff = buf.len().saturating_sub(1);
        Ok(String::from_utf8_lossy(&buf[..cutoff]).to_string())
    }

    fn at_rva<U>(&self, rva: u64) -> io::Result<U>
        where U: Byteparse + Default
    {
        self.at(self.conv_rva(rva))
    }

    fn at<U>(&self, off: u64) -> io::Result<U>
        where U: Byteparse + Default
    {
        let mut source = self.source.borrow_mut();

        source.seek(std::io::SeekFrom::Start(off))?;
        source.parse()
    }
}

fn dump_imports(pe: &PortableExecutable, w: &mut impl Write) 
    -> io::Result<()>
{
    for module in pe.imports() {
        writeln!(w, "{} {{", module.name)?;
            
        for func in &module.funcs {
            write!(w, "    ")?;
            match func {
                ImportFunc::ByName(name) => writeln!(w, "{},",   name)?,
                ImportFunc::ByOrd(ord)   => writeln!(w, "[{}],", ord)?,
            }
        }

        writeln!(w, "}}\n")?;
    }

    Ok(())
}

fn dump_exports(pe: &PortableExecutable, w: &mut impl Write) 
    -> io::Result<()>
{
    for export in pe.exports() {
        let name = export.name.as_ref()
            .unwrap_or(&"no name".to_string()).clone();
        
        write!(w, "[{:4}] {} -> ", export.ord, name)?;

        match &export.addr {
            ExportAddr::Rva(rva) => 
                write!(w, "{:016X}", rva)?,
            ExportAddr::Forwarded((m, f)) => 
                write!(w, "[{}: {}]", m, f)?
        }

        writeln!(w)?;
    }

    Ok(())
}

fn dump_sections(pe: &PortableExecutable, w: &mut impl Write) 
    -> io::Result<()>
{
    for section in pe.sections() {
        write!(w, "{: <8} [{:8X}] ", section.name, section.flags)?;
        write!(w, "(raw {:8X} -> {:8X}) ", section.raw_addr,
            section.raw_addr + section.raw_len)?;
        write!(w, "(virt {:8X} -> {:8X}) ", section.virt_addr,
            section.virt_addr + section.virt_len)?;
        writeln!(w)?;
    }

    Ok(())
}

fn main() -> io::Result<()> {
    use std::fs::File;
    use std::sync::Arc;

    // let name = if let Some(n) = std::env::args().nth(1) {
    //     n
    // } else {
    //     println!("No filename was provided.");
    //     return Ok(());
    // };

    let name = "ntoskrnl.exe";

    let mut buf = Vec::new();
    File::open(name)?.read_to_end(&mut buf)?;

    let cur = std::io::Cursor::new(&buf[..]);
    let pe  = Arc::new(PortableExecutable::parse(cur)?);

    const FILE_NAMES: [&str; 3] = [
        "sections.txt",
        "imports.txt",
        "exports.txt"
    ];

    let mut threads = Vec::new();
    for (i, filename) in FILE_NAMES.iter().enumerate() {
        let pe = pe.clone();

        threads.push(std::thread::spawn(move || {
            let mut f = File::create(filename)
                .expect("Failed to open output file.");

            match i {
                0 => dump_sections(&pe, &mut f),
                1 => dump_imports(&pe,  &mut f),
                2 => dump_exports(&pe,  &mut f),
                _ => panic!()
            }
        }));
    }

    for t in threads {
        t.join().unwrap().unwrap();
    }
    
    Ok(())
}
