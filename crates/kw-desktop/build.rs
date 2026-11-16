fn main() {
    #[cfg(windows)]
    {
        let mut res = tauri_winres::WindowsResource::new();
        res.set_icon("icons/icon.ico");
        res.set("FileDescription", "Netwarden");
        res.set("ProductName", "Netwarden");
        res.set("OriginalFilename", "netwarden.exe");
        let _ = res.compile();
    }
}
