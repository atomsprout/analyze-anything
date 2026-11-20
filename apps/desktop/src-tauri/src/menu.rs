//! The menu bar. Choosing an item tells the page, which does the work: the menu and the
//! buttons in the window are two ways to the same actions.

use tauri::menu::{Menu, MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder};
use tauri::{AppHandle, Wry};

/// Builds the menu bar in Chinese or English.
pub fn build(app: &AppHandle, english: bool) -> tauri::Result<Menu<Wry>> {
    let word = |chinese: &'static str, english_word: &'static str| if english { english_word } else { chinese };
    let item = |id: &str, text: &str, keys: Option<&str>| {
        let builder = MenuItemBuilder::with_id(id, text);
        match keys {
            Some(keys) => builder.accelerator(keys).build(app),
            None => builder.build(app),
        }
    };
    let name = "Analyze Anything";

    let app_menu = SubmenuBuilder::new(app, name)
        .item(&PredefinedMenuItem::about(app, Some(word("关于 Analyze Anything", "About Analyze Anything")), None)?)
        .separator()
        .item(&PredefinedMenuItem::services(app, Some(word("服务", "Services")))?)
        .separator()
        .item(&PredefinedMenuItem::hide(app, Some(word("隐藏 Analyze Anything", "Hide Analyze Anything")))?)
        .item(&PredefinedMenuItem::hide_others(app, Some(word("隐藏其他", "Hide Others")))?)
        .item(&PredefinedMenuItem::show_all(app, Some(word("全部显示", "Show All")))?)
        .separator()
        .item(&PredefinedMenuItem::quit(app, Some(word("退出 Analyze Anything", "Quit Analyze Anything")))?)
        .build()?;

    let export = SubmenuBuilder::new(app, word("导出", "Export"))
        .item(&item("export:pdf", "PDF…", Some("CmdOrCtrl+E"))?)
        .item(&item("export:html", "HTML…", None)?)
        .item(&item("export:md", "Markdown…", None)?)
        .item(&item("export:txt", word("纯文本…", "Plain Text…"), None)?)
        .item(&item("export:json", "JSON…", None)?)
        .item(&item("export:sarif", "SARIF…", None)?)
        .item(&item("export:sbom", word("CycloneDX 物料清单…", "CycloneDX Bill of Materials…"), None)?)
        .separator()
        .item(&item("export:folder", word("全部格式到文件夹…", "All Formats to a Folder…"), Some("CmdOrCtrl+Shift+E"))?)
        .build()?;
    let file = SubmenuBuilder::new(app, word("文件", "File"))
        .item(&item("open-file", word("打开文件…", "Open File…"), Some("CmdOrCtrl+O"))?)
        .item(&item("open-folder", word("打开文件夹…", "Open Folder…"), Some("CmdOrCtrl+Shift+O"))?)
        .separator()
        .item(&export)
        .separator()
        .item(&item("home", word("返回主页", "Back to Home"), Some("CmdOrCtrl+Shift+H"))?)
        .item(&PredefinedMenuItem::close_window(app, Some(word("关闭窗口", "Close Window")))?)
        .build()?;

    let edit = SubmenuBuilder::new(app, word("编辑", "Edit"))
        .item(&PredefinedMenuItem::undo(app, Some(word("撤销", "Undo")))?)
        .item(&PredefinedMenuItem::redo(app, Some(word("重做", "Redo")))?)
        .separator()
        .item(&PredefinedMenuItem::cut(app, Some(word("剪切", "Cut")))?)
        .item(&PredefinedMenuItem::copy(app, Some(word("拷贝", "Copy")))?)
        .item(&PredefinedMenuItem::paste(app, Some(word("粘贴", "Paste")))?)
        .item(&PredefinedMenuItem::select_all(app, Some(word("全选", "Select All")))?)
        .build()?;

    let view = SubmenuBuilder::new(app, word("显示", "View"))
        .item(&item("ai", word("AI 解读", "AI Interpretation"), Some("CmdOrCtrl+I"))?)
        .separator()
        .item(&item("lang:zh", "中文", None)?)
        .item(&item("lang:en", "English", None)?)
        .separator()
        .item(&item("theme:system", word("外观：跟随系统", "Appearance: Match System"), None)?)
        .item(&item("theme:light", word("外观：浅色", "Appearance: Light"), None)?)
        .item(&item("theme:dark", word("外观：深色", "Appearance: Dark"), None)?)
        .separator()
        .item(&PredefinedMenuItem::fullscreen(app, Some(word("进入全屏", "Enter Full Screen")))?)
        .build()?;

    let window = SubmenuBuilder::new(app, word("窗口", "Window"))
        .item(&PredefinedMenuItem::minimize(app, Some(word("最小化", "Minimize")))?)
        .item(&PredefinedMenuItem::maximize(app, Some(word("缩放", "Zoom")))?)
        .build()?;

    MenuBuilder::new(app).items(&[&app_menu, &file, &edit, &view, &window]).build()
}
