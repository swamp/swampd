use std::path::Path;
use std::{
    io,
    net::UdpSocket,
    time::{Duration, Instant},
};
use swamp::prelude::{
    compile_codegen_and_create_vm_and_run_first_time, CodeGenOptions, CodeGenResult, CompileAndCodeGenOptions,
    CompileAndVmResult, CompileCodeGenVmResult, CompileOptions, DebugInfo, GenFunctionInfo,
    HeapMemoryAddress, HostArgs, HostFunctionCallback, InstructionRange, ModuleRef, Program, RunMode,
    RunOptions, SourceMapWrapper, TypeRef, Vm, VmState,
};
use swamp_runtime::CompileResult;
use tracing::debug;

const SWAMP_PORT: i32 = 50000;

#[derive(Debug)]
pub enum Error {
    Other(String),
    IoError(io::Error),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::IoError(value)
    }
}

struct Script {
    pub resolved_program: Program,
    pub vm: Vm,
    pub code_gen: CodeGenResult,
    pub main_module: ModuleRef,
}

struct SwampDaemonCallback {}

impl HostFunctionCallback for SwampDaemonCallback {
    fn dispatch_host_call(&mut self, args: HostArgs) {
        if args.function_id == 1 { swamp_std::print::print_fn(args) }
    }
}

impl Script {
    pub fn new(
        main_module: ModuleRef,
        compile: CompileResult,
        codegen: CodeGenResult,
        vm: Vm,
    ) -> Self {
        Self {
            resolved_program: compile.program,
            vm,
            code_gen: codegen,
            main_module,
        }
    }

    pub fn get_func(&self, name: &str) -> &GenFunctionInfo {
        self.main_module
            .symbol_table
            .get_internal_function(name)
            .map_or_else(
                || {
                    panic!("source code is missing function {name}");
                },
                |found_fn| {
                    let unique_id = found_fn.program_unique_id;
                    self.code_gen.functions.get(&unique_id).map_or_else(
                        || {
                            panic!("missing codegen function for {name}");
                        },
                        |found_gen_fn| found_gen_fn,
                    )
                },
            )
    }

    pub(crate) fn get_impl_func(&self, ty: &TypeRef, func_name: &str) -> &GenFunctionInfo {
        let found_internal_def = self
            .resolved_program
            .state
            .associated_impls
            .get_internal_member_function(ty, func_name)
            .unwrap();

        self.code_gen
            .functions
            .get(&found_internal_def.program_unique_id)
            .unwrap()
    }

    pub fn execute_create_func(
        &mut self,
        func: &GenFunctionInfo,
        registers: &[HeapMemoryAddress],
        source_map_wrapper: SourceMapWrapper,
    ) {
        debug!(name=func.internal_function_definition.assigned_name, a=%registers[0], "executing create func");
        let mut standard_callback = SwampDaemonCallback {};

        self.execute_create_func_with_callback(
            func,
            registers,
            &mut standard_callback,
            source_map_wrapper,
        );
    }

    pub fn execute_create_func_with_callback(
        &mut self,
        func: &GenFunctionInfo,
        registers: &[HeapMemoryAddress],
        host_callback: &mut dyn HostFunctionCallback,
        source_map_wrapper: SourceMapWrapper,
    ) {
        debug!(name=func.internal_function_definition.assigned_name, a=%registers[0], "executing create func");

        Self::execute_returns_unit(
            func,
            registers,
            host_callback,
            &mut self.vm,
            &self.code_gen.debug_info,
            source_map_wrapper,
        );
        debug!(name=func.internal_function_definition.assigned_name,  a=%registers[0], "creation done");
    }

    pub fn execute_returns_unit(
        func: &GenFunctionInfo,
        registers: &[HeapMemoryAddress],
        callback: &mut dyn HostFunctionCallback,
        vm: &mut Vm,
        debug_info: &DebugInfo,
        source_map_wrapper: SourceMapWrapper,
    ) {
        if vm.state != VmState::Normal {
            return;
        }
        let run_options = RunOptions {
            debug_stats_enabled: false,
            debug_opcodes_enabled: false,
            debug_operations_enabled: false,
            use_color: true,
            max_count: 0,
            debug_info,
            source_map_wrapper,
            debug_memory_enabled: false,
        };

        for (index, register_value) in registers.iter().enumerate() {
            //assert!(self.simulation_value_addr < self.safe_stack_start_addr);
            assert!(
                register_value.0 == 0
                    || register_value.0 >= vm.memory().constant_memory_size as u32
            );
            if index == 0 {
                vm.set_return_register_address(register_value.0);
            } else {
                vm.set_register_pointer_addr_for_parameter(index as u8, register_value.0);
            }
        }

        vm.reset_stack_and_heap_to_constant_limit();

        run_function(vm, &func.ip_range, callback, &run_options);

        //vm.state == VmState::Normal;
    }
}

pub fn run_function(
    vm: &mut Vm,
    ip_range: &InstructionRange,
    host_function_callback: &mut dyn HostFunctionCallback,
    run_options: &RunOptions,
) {
    vm.reset_stack_and_heap_to_constant_limit();

    vm.state = VmState::Normal;

    vm.execute_from_ip(&ip_range.start, host_function_callback);

    if matches!(vm.state, VmState::Trap(_) | VmState::Panic(_)) {
        swamp_runtime::show_crash_info(vm, run_options.debug_info, &run_options.source_map_wrapper);
    }
}

fn compile_and_create_vm() -> Result<CompileCodeGenVmResult, Error> {
    let scripts_root_dir = Path::new("scripts/").to_path_buf();
    let scripts_crate_path = ["crate".to_string(), "main".to_string()];
    let compile_and_codegen = CompileAndCodeGenOptions {
        compile_options: CompileOptions {
            show_semantic: false,
            show_modules: false,
            show_errors: true,
            show_warnings: false,
            show_hints: false,
            show_information: false,
            show_types: false,
        },
        code_gen_options: CodeGenOptions {
            show_disasm: false,
            disasm_filter: None,
            show_debug: false,
            show_types: false,
            ignore_host_call: false,
        },
        skip_codegen: false,
        run_mode: RunMode::Deployed,
    };

    let should_show_information = compile_and_codegen.compile_options.show_information;

    let program = compile_codegen_and_create_vm_and_run_first_time(
        &scripts_root_dir,
        &scripts_crate_path,
        compile_and_codegen,
    );

    if let Some(compile_and_vm_result) = program {
        if let CompileAndVmResult::CompileAndVm(all_result) = compile_and_vm_result {
            

            Ok(all_result)
        } else {
            Err(Error::Other("couldn't compile".to_string()))
        }
    } else {
        Err(Error::Other("couldn't compile".to_string()))
    }
}

fn get_tick<'a>(script: &'a mut Script, lookup: SourceMapWrapper<'a>) -> &'a GenFunctionInfo {
    let simulation_new_fn = script.get_func("main").clone();
    let simulation_value_region = script.vm.memory_mut().alloc_before_stack(
        &simulation_new_fn.return_type.total_size,
        &simulation_new_fn.return_type.max_alignment,
    );

    script.execute_create_func(&simulation_new_fn, &[simulation_value_region.addr], lookup);

    script.get_impl_func(
        &simulation_new_fn
            .internal_function_definition
            .signature
            .return_type,
        "timer",
    )
}

fn main() -> Result<(), Error> {
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    println!("swampd {VERSION} booting up");
    
    let socket = UdpSocket::bind(format!("0.0.0.0:{SWAMP_PORT}"))?;

    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = [0u8; 1500];
    let mut last_time = Instant::now();

    let vm_result = compile_and_create_vm()?;
    let crate_main_path = &["crate".to_string(), "main".to_string()];

    let main_module = vm_result
        .compile
        .program
        .modules
        .get(crate_main_path)
        .expect("could not find main module")
        .clone();

    let source_map_clone = vm_result.codegen.source_map;

    let mut script = Script::new(
        main_module,
        vm_result.compile,
        vm_result.codegen.code_gen_result,
        vm_result.codegen.vm,
    );
    let wrapper = SourceMapWrapper {
        source_map: &source_map_clone,
        current_dir: Default::default(),
    };

    let tick_fn = get_tick(&mut script, wrapper).clone();

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                println!("-> {len} bytes from {peer}");
                last_time = Instant::now();
            }

            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                let since = last_time.elapsed();
                if since >= Duration::from_secs(2) {
                    let mut host_callback = SwampDaemonCallback {};
                    let wrapper = SourceMapWrapper {
                        source_map: &source_map_clone,
                        current_dir: Default::default(),
                    };
                    Script::execute_returns_unit(
                        &tick_fn,
                        &[],
                        &mut host_callback,
                        &mut script.vm,
                        &script.code_gen.debug_info,
                        wrapper,
                    );
                    last_time = Instant::now();
                }
            }

            Err(e) => {
                eprintln!("UDP recv error: {e}");
                break;
            }
        }
    }

    Ok(())
}
