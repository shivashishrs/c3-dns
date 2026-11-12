use std::fmt::Write as _;
use std::io::Write as _;

/// The web UI: `ui/index.html` is gzipped into the binary, and the hashes of its one inline
/// `<script>` and one inline `<style>` go into the page's Content-Security-Policy (no
/// 'unsafe-inline'), with an ETag over the compressed bytes.
fn ui() {
    println!("cargo:rerun-if-changed=ui/index.html");
    let html = std::fs::read_to_string("ui/index.html").expect("firmware/ui/index.html");
    let inner = |tag: &str| -> String {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        assert_eq!(html.matches(&open).count(), 1, "ui/index.html needs exactly one plain <{tag}>");
        let a = html.find(&open).unwrap() + open.len();
        let b = a + html[a..].find(&close).expect("closing tag");
        html[a..b].to_string()
    };
    use base64::Engine as _;
    use sha2::Digest as _;
    let hash = |s: &str| base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(s.as_bytes()));
    let csp = format!(
        "default-src 'self'; script-src 'sha256-{}'; style-src 'sha256-{}'; img-src 'self' data:; \
         base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        hash(&inner("script")),
        hash(&inner("style"))
    );
    let mut gz = flate2::GzBuilder::new().mtime(0).write(Vec::new(), flate2::Compression::best());
    gz.write_all(html.as_bytes()).unwrap();
    let gz = gz.finish().unwrap();
    let digest = sha2::Sha256::digest(&gz);
    let mut etag = String::from("\"");
    for b in &digest[..8] {
        write!(etag, "{b:02x}").unwrap();
    }
    etag.push('"');
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("index.html.gz"), &gz).unwrap();
    let rs = format!(
        "/// The UI page, gzipped ({} bytes from {} bytes of HTML).\n\
         pub const INDEX_GZ: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/index.html.gz\"));\n\
         pub const PAGE_CSP: &str = {csp:?};\n\
         pub const ETAG: &str = {etag:?};\n",
        gz.len(),
        html.len()
    );
    std::fs::write(out.join("ui.rs"), rs).unwrap();
    println!("cargo:warning=ui: index.html {} bytes -> {} bytes gzipped", html.len(), gz.len());
}

fn main() {
    // Only the `dev-wifi` feature reads the gitignored cfg.toml (to seed NVS on a development
    // board); the default build carries no credentials and is provisioned through the portal.
    println!("cargo:rerun-if-changed=cfg.toml");
    if std::env::var_os("CARGO_FEATURE_DEV_WIFI").is_some() && !std::path::Path::new("cfg.toml").exists() {
        println!("cargo:warning=dev-wifi: firmware/cfg.toml not found; nothing to seed (copy cfg.toml.example)");
    }
    ui();
    embuild::espidf::sysenv::output();
}
