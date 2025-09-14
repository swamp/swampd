use std::fs;
use std::path::Path;
use bytesize::ByteSize;
use tracing::{debug, info, warn};

pub struct SwampdIniVM {
    pub heap_size: usize,
    pub stack_size: usize,
}

pub struct SwampdIni {
    pub vm: SwampdIniVM,
}

pub fn overwrite(ini: &mut SwampdIni, obj: yini::Object) {
    if let Some(vm_value) = obj.get("vm") {
        let vm = vm_value.as_object().unwrap();

        if let Some(found) = vm.get("heap") {
            let bs: ByteSize = found.as_str().unwrap().parse().unwrap();
            ini.vm.heap_size = bs.0 as usize;
        }

        if let Some(found) = vm.get("stack") {
            let bs: ByteSize = found.as_str().unwrap().parse().unwrap();
            ini.vm.stack_size = bs.0 as usize;
        }
    }
}

pub fn read_yini(path: &Path) -> SwampdIni {
    let mut ini = SwampdIni {
        vm: SwampdIniVM {
            stack_size: 512 * 1024 * 1024,
            heap_size: 128 * 1024,
        }
    };

    debug!("reading yini file from {}", path.display());

    let result = fs::read_to_string(path);
    if let Ok(new_str) = result {
        let obj = yini::Parser::new(&new_str).parse();

        overwrite(&mut ini, obj);
    } else {
        warn!("failed to parse yini file");
    }

    ini
}
