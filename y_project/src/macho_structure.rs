#[allow(dead_code)]
#[derive(Debug)]
pub struct MachOHeader<'a> {
    pub magic: &'a [u8],
    pub cputype: &'a [u8],
    pub cpusubtype: &'a [u8],
    pub ftype: &'a [u8],
    pub lcnum: &'a [u8],
    pub lcsize: &'a [u8],
    pub flags: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct LoadCommand<'a> {
    pub cmd: &'a [u8],
    pub cmdsize: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SegmentCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub segname: &'a [u8],
    pub vmaddr: &'a [u8],
    pub vmsize: &'a [u8],
    pub fileoff: &'a [u8],
    pub filesize: &'a [u8],
    pub maxprot: &'a [u8],
    pub initprot: &'a [u8],
    pub nsects: &'a [u8],
    pub flags: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SectionCommand<'a> {
    pub sectname: &'a [u8],
    pub segname: &'a [u8],
    pub addr: &'a [u8],
    pub size: &'a [u8],
    pub symbol_table_for_offset: &'a [u8],
    pub align: &'a [u8],
    pub reloff: &'a [u8],
    pub nreloc: &'a [u8],
    pub flags: &'a [u8],
    pub reserved: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DylibCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub name_offset: &'a [u8],
    pub timestamp: &'a [u8],
    pub current_version: &'a [u8],
    pub compatibility_version: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SymtabCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub symoff: &'a [u8],
    pub nsyms: &'a [u8],
    pub stroff: &'a [u8],
    pub strsize: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SymsegCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub symbol_table_for_offset: &'a [u8],
    pub size: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]

pub struct EntryPointCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub entryoff: &'a [u8],
    pub stacksize: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RoutineCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub init_address: &'a [u8],
    pub init_module: &'a [u8],
    pub reserved_bytes: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DysymtabCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub ilocalsym: &'a [u8],
    pub nlocalsym: &'a [u8],
    pub iextdefsym: &'a [u8],
    pub nextdefsim: &'a [u8],
    pub iundefsym: &'a [u8],
    pub nundefsym: &'a [u8],
    pub tocoff: &'a [u8],
    pub ntoc: &'a [u8],
    pub modtaboff: &'a [u8],
    pub nmodtab: &'a [u8],
    pub extrefsymoff: &'a [u8],
    pub nextrefsyms: &'a [u8],
    pub indirectsymoff: &'a [u8],
    pub nindirectsyms: &'a [u8],
    pub extreloff: &'a [u8],
    pub nextre1: &'a [u8],
    pub locreloff: &'a [u8],
    pub nlocre1: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct PrebindChecksumCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub cksum: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct UUIDCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub uuid: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ThreadCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub flavor: &'a [u8],
    pub count: &'a [u8],
    pub state: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct EncryptionInfoCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub cryptoff: &'a [u8],
    pub cryptsize: &'a [u8],
    pub cryptid: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct VersionMinCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub version: &'a [u8],
    pub sdk: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct LinkEditDataCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub dataoff: &'a [u8],
    pub datasize: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DyldInfoCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub rebase_off: &'a [u8],
    pub rebase_size: &'a [u8],
    pub bind_off: &'a [u8],
    pub bind_size: &'a [u8],
    pub weak_bind_off: &'a [u8],
    pub weak_bind_size: &'a [u8],
    pub lazy_bind_off: &'a [u8],
    pub lazy_bind_size: &'a [u8],
    pub export_of: &'a [u8],
    pub export_size: &'a [u8],
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RunPathCommand<'a> {
    pub load_cmd: LoadCommand<'a>,
    pub symbol_table_for_offset: &'a [u8],
}

#[allow(dead_code)]
pub enum LoadCommandData<'a> {
    Segment(SegmentCommand<'a>),
    Symtab(SymtabCommand<'a>),
    Dymlib(DylibCommand<'a>),
    Dysymtab(DysymtabCommand<'a>),
    Routine(RoutineCommand<'a>),
    EntryPoint(EntryPointCommand<'a>),
    Symseg(SymsegCommand<'a>),
    PrebindChecksum(PrebindChecksumCommand<'a>),
    UUID(UUIDCommand<'a>),
    Thread(ThreadCommand<'a>),
    EncryptionInfo(EncryptionInfoCommand<'a>),
    VersionMin(VersionMinCommand<'a>),
    RunPath(RunPathCommand<'a>),
    DyldInfo(DyldInfoCommand<'a>),
    LinkEditData(LinkEditDataCommand<'a>),
}
