//! Phase 1 CLI demo: show fail-closed line+reason vs good config.
use std::path::PathBuf;

fn main() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/config");
    for name in ["good.toml", "bad_line_12.toml"] {
        let path = base.join(name);
        print!("== {name}: ");
        match sedat::config::parse_toml(&std::fs::read_to_string(&path).unwrap()) {
            Ok(c) => println!("OK schema_version={}", c.schema_version),
            Err(e) => println!("FAIL: {e}"),
        }
    }
}
