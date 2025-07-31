use seq_map::SeqMap;
use swamp::prelude::{BasicTypeRef, CodeGenResult, GenFunctionInfo};

#[must_use] pub fn build_single_param_function_dispatch(
    code_gen: &CodeGenResult,
    return_type: &BasicTypeRef,
) -> SeqMap<u32, GenFunctionInfo> {
    let mut function_map = SeqMap::new();

    for (_unique_id, gen_func) in &code_gen.functions {
        if gen_func.params.len() == 2 {
            let first_param = &gen_func.params[0];

            if first_param.id.0 == return_type.id.0 {
                let second_param_type = &gen_func.params[1];

                let universal_hash = second_param_type.universal_hash_u64() as u32;

                println!(
                    "Registering function 0x{:08x} '{}' with parameter type (param type: {:?})",
                    universal_hash,
                    gen_func.internal_function_definition.assigned_name,
                    second_param_type
                );

                let _ = function_map.insert(universal_hash, gen_func.clone());
            }
        }
    }

    function_map
}
