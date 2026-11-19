//! Serves a kept report as its HTML page, for the frame the app shows it in.
//!
//! The address is `report://localhost/<id>?lang=zh|en&host=1`. The page is the same
//! self-contained `report.html` the command line writes: it carries its own strict content
//! security policy and needs nothing else, so this is the only thing the `report` scheme serves.

use tauri::Manager;
use tauri::http::{Request, Response, StatusCode, header};

use aa_app::export::{self, Kind, Lang};

use crate::state::AppState;

fn plain(status: StatusCode, text: &str) -> Response<Vec<u8>> {
    let mut response = Response::new(text.as_bytes().to_vec());
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

/// Answers one request for a report page.
pub fn serve(app: &tauri::AppHandle, request: &Request<Vec<u8>>) -> Response<Vec<u8>> {
    let uri = request.uri();
    let id = uri.path().trim_matches('/');
    let lang = match uri.query().unwrap_or("").split('&').find_map(|pair| pair.strip_prefix("lang=")) {
        Some("zh") => Lang::Zh,
        _ => Lang::En,
    };
    let state = app.state::<AppState>();
    let report = match state.report(id) {
        Ok(report) => report,
        Err(message) => return plain(StatusCode::NOT_FOUND, &message),
    };
    match export::render(&report, Kind::Html, lang, &[]) {
        Ok(page) => {
            let mut response = Response::new(page);
            let headers = response.headers_mut();
            headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/html; charset=utf-8"));
            // Rendered anew each time it is asked for; nothing should keep an old copy.
            headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
            headers.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
            response
        }
        Err(message) => plain(StatusCode::INTERNAL_SERVER_ERROR, &message),
    }
}
