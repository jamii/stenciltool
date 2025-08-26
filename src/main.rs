use std::{env, fs};
use std::error::Error;
use goblin::{elf, Object};
use minijinja::{Environment, context};
use serde;
use clap::Parser;

#[derive(serde::Serialize)]
struct Hole<'a> {
    name: &'a str,
    index: usize,
    datatype: &'static str,
    internal: bool,
}

#[derive(serde::Serialize)]
struct Reloc<'a> {
    offset: u64,
    addend: i64,
    hole: &'a Hole<'a>,
    relocation: &'static str,
}

#[derive(serde::Serialize)]
struct Stencil<'a, 'b> {
    name: &'a str,
    address: u64,
    size: u64,
    code: &'a [u8],
    relocs: Vec<Reloc<'b>>,
    holes: Vec<&'b Hole<'b>>,
}

fn read_elf<'a: 'b, 'b>(data: &'a Vec<u8>, stencils: &mut Vec<Stencil<'a, 'a>>, holes: &'a mut Vec<Hole<'b>>) -> Result<(), Box<dyn Error>> {
    let object = Object::parse(&*data)?;
    let elf = match object {
        Object::Elf(x) => x,
        _ => unreachable!("object file is not elf"),
    };
    let (text_index, text) = elf.section_headers.iter().enumerate().find(|(_, shdr)| {
        let name = elf.shdr_strtab.get_at(shdr.sh_name);
        name == Some(".text")
    })
    .expect("No .text segment");
    
    for (index, symbol) in elf.syms.iter().enumerate() {
        if symbol.st_bind() != elf::sym::STB_GLOBAL ||
           symbol.st_type() != elf::sym::STT_FUNC {
            let name = elf.strtab.get_at(symbol.st_name).ok_or("symbol missing in strtab")?;
            let datatype_opt = match name {
                name if name.starts_with("cnp_large_value_hole") => Some("uint64_t"),
                name if name.starts_with("cnp_small_value_hole") => Some("uint32_t"),
                name if name.starts_with("cnp_near_func_hole") => Some("uint32_t"),
                name if name.starts_with("cnp_far_fun_hole") => Some("void*"),
                name if name == "cnp_stencil_output" => Some("uint32_t"),
                _ => None,
            };
            if let Some(datatype) = datatype_opt {
                holes.push(Hole {
                    name: name,
                    index: index,
                    datatype: datatype,
                    internal: true,
                });
            } else {
                holes.push(Hole {
                    name: name,
                    index: index,
                    datatype: "void*",
                    internal: false,
                });
            }
            continue
        }
        let name = elf.strtab.get_at(symbol.st_name).ok_or("symbol missing in strtab")?;
        let start = (text.sh_offset + symbol.st_value) as usize;
        let size = symbol.st_size as usize;
        stencils.push( Stencil {
            name: name,
            address: symbol.st_value,
            size: symbol.st_size,
            code: &data[start .. start + size],
            relocs: Vec::new(),
            holes: Vec::new(),
        });
    }

    let (_, reloc_section) = elf.shdr_relocs.iter()
        .find(|(idx, _)| *idx==text_index+1)
        .expect("no relocations in .text");
    for reloc in reloc_section.iter() {
        if let Some(stencil) = stencils.iter_mut().find(|s| (s.address..s.address+s.size).contains(&reloc.r_offset)) {
            stencil.relocs.push( Reloc {
                offset: reloc.r_offset - stencil.address,
                addend: reloc.r_addend.unwrap_or(0),
                hole: &holes.iter().find(|h| h.index == reloc.r_sym).unwrap(),
                relocation: elf::reloc::r_to_str(reloc.r_type, elf::header::EM_X86_64),
            });
        }
    }

    Ok(())
}


fn trim_trailing_jmp(stencils : &mut Vec<Stencil>) -> () {
    // If the last reloc is a jump to cnp_stencil_output, then remove it.
    for stencil in stencils.iter_mut() {
        if let Some(lastreloc) = stencil.relocs.last() {
            let codelen = stencil.size as usize;
            if lastreloc.offset == stencil.size - 4 &&
               lastreloc.hole.name == "cnp_stencil_output" &&
               stencil.code[codelen-5..codelen] == [0xe9,0,0,0,0] {
                stencil.code = &stencil.code[0..codelen-5];
                stencil.relocs.pop();
            }
        }
    }
}

fn populate_stencil_holes<'a>(stencils : &mut Vec<Stencil<'a,'a>>) -> () {
    // Populate the list of holes used to make codegen eaiser.
    for stencil in stencils.iter_mut() {
        for reloc in stencil.relocs.iter() {
            let missing_hole = stencil.holes.iter().find(|h| h.index == reloc.hole.index).is_none();
            if missing_hole {
                stencil.holes.push(&reloc.hole);
            }
        }
    }
}

fn hex_filter(value: minijinja::Value) -> String {
    let hex_strings: Vec<String> = value.try_iter().expect("no code")
        .map(|b| format!("0x{:02x}", b.as_usize().expect("number")))
        .collect();
    hex_strings.join(", ")
}

fn emit_code(stencils : &Vec<Stencil>, holes : &Vec<Hole>, header: &str, source: &str) -> Result<(), Box<dyn Error>> {
    for stencil in stencils.iter() {
        println!("{}: {}", stencil.name, hex::encode(stencil.code));
        for reloc in stencil.relocs.iter() {
            println!(" {}: {} {}", reloc.offset, reloc.hole.name, reloc.relocation);
        }
    }

    let mut env = Environment::new();
    env.add_filter("hex", hex_filter);
    minijinja_embed::load_templates!(&mut env);

    let source_tmpl = env.get_template("source.jinja").unwrap();
    let source_rendered = source_tmpl.render(context!(stencils => stencils, holes => holes, header => header)).unwrap();
    fs::write(source, source_rendered)?;

    let header_tmpl = env.get_template("header.jinja").unwrap();
    let header_rendered = header_tmpl.render(context!(stencils => stencils)).unwrap();
    fs::write(header, header_rendered)?;

    Ok(())
}

#[derive(Parser, Debug)]
struct Args {
    object: String,
    #[arg(long)]
    header: String,
    #[arg(long)]
    source: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let mut holes = Vec::<Hole>::new();
    let mut stencils = Vec::<Stencil>::new();
    let data = fs::read(args.object)?;
    read_elf(&data, &mut stencils, &mut holes)?;
    
    trim_trailing_jmp(&mut stencils);
    populate_stencil_holes(&mut stencils);

    emit_code(&stencils, &holes, &args.header, &args.source)?;

    Ok(())
}
