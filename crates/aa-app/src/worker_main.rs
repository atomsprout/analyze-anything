//! A worker process for this crate's tests. The desktop app starts itself as its worker.

fn main() {
    aa_worker::serve_process(std::io::stdin().lock(), std::io::stdout());
}
