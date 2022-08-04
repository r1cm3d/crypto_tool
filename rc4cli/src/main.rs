use clap::Parser;
use rc4::Rc4;
use std::fs::File;
use std::io::prelude::{Read, Seek, Write};

/// RC4 file en/decryption

#[derive(Parser, Debug)]
struct Args {
    /// Name of fiel to en/decrypt
    #[clap(short, long, required = true, value_name = "FILE_NAME")] 
    file: String,

    /// En/Decryption key (hexadecimal bytes)
    #[clap(
        short,
        long,
        required = true,
        value_name = "HEX_BYTES",
        min_values = 5,
        max_values = 256
        )]
    key: Vec<String>,    
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let mut contents = Vec::new();

    let key_bytes = args
            .key
            .iter()
            .map(|s| s.trim_start_matches("0x"))
            .map(|s| u8::from_str_radix(s, 16).expect("Invalid key hex byte"))
            .collect::<Vec<u8>>();

    let mut file = File::options().read(true).write(true).open(&args.file)?;

    file.read_to_end(&mut contents)?;

    Rc4::apply_keystream_static(&key_bytes, &mut contents);

    file.rewind()?;
    file.write_all(&contents)?;

    println!("Processed {}", args.file);

    Ok(())
}
