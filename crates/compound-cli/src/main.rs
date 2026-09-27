use compound_cli::{run, CliError};

fn main() {
    match run(std::env::args_os().skip(1)) {
        Ok(code) => {
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(CliError::Help(message)) => {
            println!("{message}");
        }
        Err(error) => {
            eprintln!("compound: {error}");
            std::process::exit(1);
        }
    }
}
