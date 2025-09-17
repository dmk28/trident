use crate::plugins::core::Plugin;
use libloading::{Library, Symbol};
use std::path::Path;

type PluginCreate = fn() -> Box<dyn Plugin>;

pub fn load_native_plugin(
    library_path: &Path,
) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error>> {
    let lib = unsafe { Library::new(library_path)? };
    let create_plugin: Symbol<PluginCreate> = unsafe { lib.get(b"create_plugin")? };

    let plugin = create_plugin();

    std::mem::forget(lib);

    Ok(plugin)
}
