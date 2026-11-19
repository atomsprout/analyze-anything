//! A worker and nothing else: reads requests on standard input, answers on standard output.
//! The desktop app does not ship this program; it starts itself as a worker instead.

fn main() {
    aa_worker::serve(std::io::stdin().lock(), std::io::stdout());
}
