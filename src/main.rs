/*
 * Copyright (c) Peter Bjorklund. All rights reserved. https://github.com/swamp/swampd
 * Licensed under the MIT License. See LICENSE in the project root for license information.
 */

pub mod scan;
use crate::scan::build_single_param_function_dispatch;
use bytes::{BufMut, BytesMut};
use frag_datagram::server::address_hash;
use frag_datagram::ServerHub;
use pico_args::Arguments;
use redis::{Client, Connection, RedisError, TypedCommands};
use source_map_cache::SourceMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::{
    env, io,
    net::UdpSocket,
    ptr,
    time::{Duration, Instant},
};
use swamp::prelude::{
    compile_codegen_and_create_vm_and_run_first_time, BasicTypeKind, CodeGenOptions, CodeGenResult, CompileAndCodeGenOptions,
    CompileAndVmResult, CompileCodeGenVmResult, CompileOptions, DebugInfo, GenFunctionInfo,
    HeapMemoryAddress, HeapMemoryRegion, HostArgs, HostFunctionCallback, InstructionRange,
    MemoryAlignment, MemorySize, ModuleRef, Program, RunMode, RunOptions, SourceMapWrapper, TypeCache, TypeRef,
    Vm, VmState,
};
use swamp_runtime::CompileResult;
use swamp_vm::prelude::AnyValue;
use swamp_vm_layout::LayoutCache;
use tracing::{debug, info, trace, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[derive(Debug)]
pub enum RegisterValue {
    HeapMemoryAddress(HeapMemoryAddress),
    Scalar(u32),
}

impl RegisterValue {
    pub fn raw(&self) -> u32 {
        match self {
            RegisterValue::HeapMemoryAddress(a) => a.0,
            RegisterValue::Scalar(s) => *s,
        }
    }
}

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

impl From<pico_args::Error> for Error {
    fn from(value: pico_args::Error) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<RedisError> for Error {
    fn from(value: RedisError) -> Self {
        Self::Other(value.to_string())
    }
}

struct Script {
    pub resolved_program: Program,
    pub vm: Vm,
    pub code_gen: CodeGenResult,
    pub main_module: ModuleRef,
    simulation_value_region: HeapMemoryRegion,
}

pub struct UdpResponse<'a> {
    pub udp_socket: &'a UdpSocket,
    pub sock_addr: SocketAddr,
    pub connection_id: u16,
}

impl<'a> UdpResponse<'a> {
    pub fn new(udp_socket: &'a UdpSocket) -> Self {
        Self {
            udp_socket,
            sock_addr: SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            connection_id: 0,
        }
    }
}

struct InitDaemonCallback {}

impl HostFunctionCallback for InitDaemonCallback {
    fn dispatch_host_call(&mut self, args: HostArgs) {
        match args.function_id {
            1 => swamp_std::print::print_fn(args),
            _ => panic!("unknown"),
        }
    }
}

struct DbApi<'a> {
    pub type_cache: &'a LayoutCache,
    pub client: &'a mut Client,
}

impl<'a> DbApi<'a> {
    pub fn db_set(&mut self, args: HostArgs) {
        // ignore self at 1
        let key_string = args.string(2);
        let struct_value = args.any(3);
        trace!(hash=?struct_value.type_hash, "struct has hash");
        let basic_type = self.type_cache.universal_short_id(struct_value.type_hash);
        if let BasicTypeKind::Struct(struct_type) = &basic_type.kind {
            let mut tuples = Vec::new();
            for field in &struct_type.fields {
                let key = field.name.clone();
                let value = match &field.ty.kind {
                    BasicTypeKind::U8 => "u8",
                    BasicTypeKind::B8 => "b8",
                    BasicTypeKind::U16 => "u16",
                    BasicTypeKind::S32 => "s32",
                    BasicTypeKind::Fixed32 => "f32",
                    BasicTypeKind::U32 => "u32",
                    BasicTypeKind::StringView { .. } => "strview",
                    _ => panic!("can not serialize"),
                };
                tuples.push((key, value));
            }

            self.client
                .hset_multiple(key_string, &tuples)
                .unwrap()
        } else {
            panic!("was not struct. internal error");
        }
    }

    pub fn db_get(&mut self, args: HostArgs) {
        let key_string = args.string(1);
        //        self.client.set(key_string, )
    }
}

struct SwampDaemonCallback<'a> {
    server_hub: &'a mut ServerHub,
    db_api: DbApi<'a>,
    response: &'a UdpResponse<'a>,
}

impl<'a> SwampDaemonCallback<'a> {
    pub(crate) fn db_new(&self, p0: HostArgs) {
        // intentionally do nothing for now
    }
}

pub fn send_back(server_hub: &mut ServerHub, udp_response: &UdpResponse, any_value: AnyValue) {
    let mut buf = BytesMut::with_capacity(2 + 4 + any_value.bytes.len());
    buf.put_u32_le(any_value.type_hash);
    buf.put_slice(&any_value.bytes);

    let datagrams = server_hub
        .send_to(udp_response.connection_id, &buf)
        .unwrap();

    for datagram in datagrams {
        //trace!(addr=%udp_response.sock_addr, octet_count,  payload_octet_count = any_value.bytes.len(), "sending back {:X}", any_value.type_hash);
        udp_response
            .udp_socket
            .send_to(&datagram, udp_response.sock_addr)
            .unwrap();
    }
}

impl HostFunctionCallback for SwampDaemonCallback<'_> {
    fn dispatch_host_call(&mut self, mut args: HostArgs) {
        match args.function_id {
            1 => swamp_std::print::print_fn(args),
            10 => send_back(&mut self.server_hub, &self.response, args.any(2)),
            11 => args.set_register(0, self.response.connection_id as u32),
            50 => {
                // true_random()
                let mut data = [0u8; 4];
                getrandom::fill(&mut data).unwrap();
                let random_int = u32::from_le_bytes(data);
                args.set_register(0, random_int)
            }
            500 => {} //self.db_api.db_new(args),
            501 => self.db_api.db_set(args),
            502 => self.db_api.db_get(args),
            _ => panic!("unknown"),
        }
    }
}

struct TimeoutDaemonCallback<'a> {
    db_api: DbApi<'a>,
}

impl<'a> TimeoutDaemonCallback<'a> {}

impl HostFunctionCallback for TimeoutDaemonCallback<'_> {
    fn dispatch_host_call(&mut self, args: HostArgs) {
        match args.function_id {
            1 => swamp_std::print::print_fn(args),
            10 => {}
            501 => self.db_api.db_set(args),
            502 => self.db_api.db_get(args),
            _ => panic!("unknown"),
        }
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
            simulation_value_region: HeapMemoryRegion {
                addr: HeapMemoryAddress(0),
                size: MemorySize(0),
            },
        }
    }

    pub fn get_func(&self, name: &str) -> &GenFunctionInfo {
        self.main_module
            .definition_table
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
        if let Some(found_internal_def) = self
            .resolved_program
            .state
            .associated_impls
            .get_internal_member_function(ty, func_name)
        {
            self.code_gen
                .functions
                .get(&found_internal_def.program_unique_id)
                .unwrap()
        } else {
            panic!("must have function {func_name} on type {ty}")
        }
    }

    pub fn execute_create_func(
        &mut self,
        func: &GenFunctionInfo,
        registers: &[RegisterValue],
        source_map_wrapper: SourceMapWrapper,
    ) {
        debug!(name=func.internal_function_definition.assigned_name, a=?registers[0], "executing create func");
        let mut standard_callback = InitDaemonCallback {};

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
        registers: &[RegisterValue],
        host_callback: &mut dyn HostFunctionCallback,
        source_map_wrapper: SourceMapWrapper,
    ) {
        debug!(name=func.internal_function_definition.assigned_name, a=?registers[0], "executing create func with callback");

        Self::execute_returns_unit(
            func,
            registers,
            host_callback,
            &mut self.vm,
            &self.code_gen.debug_info,
            source_map_wrapper,
        );
        debug!(name=func.internal_function_definition.assigned_name,  a=?registers[0], "creation done");
    }

    pub fn execute_returns_unit(
        func: &GenFunctionInfo,
        registers: &[RegisterValue],
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
            match register_value {
                RegisterValue::HeapMemoryAddress(a) => {
                    assert!(a.0 == 0 || a.0 >= vm.memory().constant_memory_size as u32);
                }
                _ => {}
            }
            if index == 0 {
                vm.set_return_register_address(register_value.raw());
            } else {
                vm.set_register_pointer_addr_for_parameter(index as u8, register_value.raw());
            }
        }

        vm.reset_heap_allocator();

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
    vm.reset_heap_allocator();

    vm.state = VmState::Normal;

    vm.execute_from_ip(&ip_range.start, host_function_callback);

    if matches!(vm.state, VmState::Trap(_) | VmState::Panic(_)) {
        swamp_runtime::show_crash_info(vm, run_options.debug_info, &run_options.source_map_wrapper);
    }
}

fn compile_and_create_vm(source_map: &mut SourceMap) -> Result<CompileCodeGenVmResult, Error> {
    let scripts_crate_path = ["crate".to_string(), "main".to_string()];
    let compile_and_codegen = CompileAndCodeGenOptions {
        compile_options: CompileOptions {
            show_semantic: false,
            show_modules: false,
            show_errors: true,
            show_warnings: false,
            show_hints: true,
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

    //let should_show_information = compile_and_codegen.compile_options.show_information;

    let program = compile_codegen_and_create_vm_and_run_first_time(
        source_map,
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

fn create_script_server<'a>(script: &'a mut Script, lookup: SourceMapWrapper<'a>) -> TypeRef {
    let simulation_new_fn = script.get_func("main").clone();
    let simulation_value_region = script.vm.memory_mut().alloc_before_stack(
        &simulation_new_fn.return_type.total_size,
        &simulation_new_fn.return_type.max_alignment,
    );

    script.execute_create_func(
        &simulation_new_fn,
        &[RegisterValue::HeapMemoryAddress(
            simulation_value_region.addr,
        )],
        lookup,
    );

    script.simulation_value_region = simulation_value_region;

    simulation_new_fn
        .internal_function_definition
        .signature
        .return_type
        .clone()
}

fn do_get_tick<'a>(script: &'a mut Script, server_type: &TypeRef) -> &'a GenFunctionInfo {
    script.get_impl_func(&server_type, "timer")
}

const DEFAULT_PORT: u16 = 50000;
const DEFAULT_DATA_DIR: &str = "./data";
const DEFAULT_SCRIPTS_DIR: &str = "./scripts";

fn print_usage() {
    eprintln!(
        "Usage: swampd [options]\n\n\
         Options:\n\
         \t-C, --chdir <DIR>            Change working directory before anything else\n\
         \t-s, --scripts-dir <DIR>      Path to Swamp scripts (default: {DEFAULT_SCRIPTS_DIR})\n\
         \t-p, --port <PORT>            UDP port to bind (default: {DEFAULT_PORT})\n\
         \t-d, --data-dir <DIR>         Path for keydb storage (default: {DEFAULT_DATA_DIR})\n\
         \t-h, --help                   Print this help message"
    );
}

pub struct ScriptDatagrams {
    pub handle: i32,
}

fn main() -> Result<(), Error> {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(true);
    let filter_layer = EnvFilter::from_default_env();
    Registry::default()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    const VERSION: &str = env!("CARGO_PKG_VERSION");

    println!("swampd {VERSION} booting up");

    let mut args = Arguments::from_env();

    if args.contains(["-h", "--help"]) {
        print_usage();
        return Ok(());
    }
    let mut client = redis::Client::open("redis://127.0.0.1/")?;

    let mut con: Connection = client.get_connection().inspect_err(|err| {
        eprintln!("error: please start keydb. example: keydb-server /opt/homebrew/etc/keydb.conf")
    })?;

    // TODO: Remove this redis test
    con.set("foo", "bar")?;
    let val: Option<String> = con.get("foo")?;

    let chdir: Option<PathBuf> = args.opt_value_from_str(["-C", "--chdir"])?;
    if let Some(dir) = chdir {
        env::set_current_dir(&dir)
            .map_err(|e| Error::Other(format!("failed to chdir to {dir:?}: {e}")))?;
    }

    let port = args
        .opt_value_from_str(["-p", "--port"])?
        .unwrap_or(DEFAULT_PORT);
    info!(port, "start listening");

    let data_dir: PathBuf = args
        .opt_value_from_str(["-d", "--data-dir"])?
        .unwrap_or_else(|| DEFAULT_DATA_DIR.into());

    let scripts_dir: PathBuf = args
        .opt_value_from_str(["-s", "--scripts-dir"])?
        .unwrap_or_else(|| DEFAULT_SCRIPTS_DIR.into());

    let _ = args.finish();

    let socket = UdpSocket::bind(format!("0.0.0.0:{port}"))?;

    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = [0u8; 1500];
    let mut last_time = Instant::now();

    let mut source_map = swamp_compile::create_source_map(Path::new("packages"), &scripts_dir)?;

    let vm_result = compile_and_create_vm(&mut source_map)?;

    let crate_main_path = &["crate".to_string(), "main".to_string()];

    let main_module = vm_result
        .compile
        .program
        .modules
        .get(crate_main_path)
        .expect("could not find main module")
        .clone();

    let mut script = Script::new(
        main_module,
        vm_result.compile,
        vm_result.codegen.code_gen_result,
        vm_result.codegen.vm,
    );
    let wrapper = SourceMapWrapper {
        source_map: &source_map,
        current_dir: PathBuf::default(),
    };

    let server_type = create_script_server(&mut script, wrapper);

    let tick_fn = do_get_tick(&mut script, &server_type).clone();

    let on_connected_fn = script.get_impl_func(&server_type, "on_connected").clone();
    let on_disconnected_fn = script
        .get_impl_func(&server_type, "on_disconnected")
        .clone();

    let dispatch_map = build_single_param_function_dispatch(&script.code_gen, &tick_fn.params[0]);

    let incoming_param_mem_region = script
        .vm
        .memory_mut()
        .alloc_before_stack(&MemorySize(32768), &MemoryAlignment::U64);

    let mut receiver_hub = frag_datagram::ServerHub::new(10, 20, 2);

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                trace!(len, ?peer, "bytes received from peer");

                last_time = Instant::now();

                if len < 8 {
                    eprintln!("Packet too small: {len} bytes (minimum 8 bytes required)");
                    continue;
                }

                let addr_hash = match peer {
                    SocketAddr::V4(addr) => {
                        address_hash::hash_ipv4((*addr.ip()).into(), addr.port())
                    }
                    SocketAddr::V6(addr) => {
                        address_hash::hash_ipv6(addr.ip().octets(), addr.port())
                    }
                };
                trace!(addr_hash, "calculated sock addr hash");

                if let Some((connection_id, payload, responses, is_new_connection)) =
                    receiver_hub.receive(&buf[0..len], addr_hash)
                {
                    let mut host_callback = SwampDaemonCallback {
                        server_hub: &mut receiver_hub,
                        db_api: DbApi {
                            client: &mut client,
                            type_cache: &script.code_gen.layout_cache,
                        },
                        response: &UdpResponse {
                            udp_socket: &socket,
                            sock_addr: SocketAddr::from(peer),
                            connection_id,
                        },
                    };

                    let wrapper = SourceMapWrapper {
                        source_map: &source_map,
                        current_dir: PathBuf::default(),
                    };

                    trace!(is_new_connection, "was it new");
                    if is_new_connection {
                        Script::execute_returns_unit(
                            &on_connected_fn,
                            &[
                                RegisterValue::HeapMemoryAddress(HeapMemoryAddress(0)), // no return value
                                RegisterValue::HeapMemoryAddress(
                                    script.simulation_value_region.addr, // self
                                ),
                                RegisterValue::HeapMemoryAddress(HeapMemoryAddress(0)), // `Datagrams` has no size
                            ],
                            &mut host_callback,
                            &mut script.vm,
                            &script.code_gen.debug_info,
                            wrapper,
                        );
                    }

                    // Parse payload size (next 4 bytes, little-endian)
                    let universal_hash =
                        u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);

                    if let Some(gen_func_info) = dispatch_map.get(&universal_hash) {
                        // The actual payload starts at byte 4
                        let inner_payload = &payload[4..payload.len()];

                        let expected_size = gen_func_info.params[1].total_size.0;

                        if inner_payload.len() == expected_size as usize {
                            unsafe {
                                let target_ptr = script
                                    .vm
                                    .memory_mut()
                                    .get_heap_ptr(incoming_param_mem_region.addr.0 as usize);

                                ptr::copy_nonoverlapping(
                                    inner_payload.as_ptr(),
                                    target_ptr,
                                    payload.len(),
                                );
                            }

                            trace!(
                                name = gen_func_info.internal_function_definition.assigned_name,
                                "calling swamp function"
                            );

                            let wrapper = SourceMapWrapper {
                                source_map: &source_map,
                                current_dir: PathBuf::default(),
                            };

                            Script::execute_returns_unit(
                                gen_func_info,
                                &[
                                    RegisterValue::HeapMemoryAddress(HeapMemoryAddress(0)), // no return
                                    RegisterValue::HeapMemoryAddress(
                                        script.simulation_value_region.addr, // self
                                    ),
                                    RegisterValue::HeapMemoryAddress(
                                        incoming_param_mem_region.addr, // message
                                    ),
                                    RegisterValue::HeapMemoryAddress(HeapMemoryAddress(0)), // `Datagrams` has no size
                                ],
                                &mut host_callback,
                                &mut script.vm,
                                &script.code_gen.debug_info,
                                wrapper,
                            );
                        } else {
                            warn!(
                                expected_size,
                                encountered_size = inner_payload.len(),
                                "payload size is wrong for this type"
                            )
                        }
                    } else {
                        warn!(universal_hash, "unknown universal type hash");
                    }
                } else {
                    warn!("unknown datagram");
                }
            }

            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                let since = last_time.elapsed();
                if since >= Duration::from_secs(2) {
                    let mut host_callback = TimeoutDaemonCallback {
                        db_api: DbApi {
                            client: &mut client,
                            type_cache: &script.code_gen.layout_cache,
                        },
                    };
                    let wrapper = SourceMapWrapper {
                        source_map: &source_map,
                        current_dir: PathBuf::default(),
                    };

                    let removed_connections = receiver_hub.cleanup_inactive_connections();
                    if !removed_connections.is_empty() {
                        for removed_connection in removed_connections {
                            trace!(removed_connection, "remove connection");
                            let wrapper = SourceMapWrapper {
                                source_map: &source_map,
                                current_dir: PathBuf::default(),
                            };
                            Script::execute_returns_unit(
                                &on_disconnected_fn,
                                &[
                                    RegisterValue::HeapMemoryAddress(HeapMemoryAddress(0)), // no return value
                                    RegisterValue::HeapMemoryAddress(
                                        script.simulation_value_region.addr, // self
                                    ),
                                    RegisterValue::Scalar(removed_connection as u32), // connection id
                                ],
                                &mut host_callback,
                                &mut script.vm,
                                &script.code_gen.debug_info,
                                wrapper,
                            );
                        }
                    }

                    Script::execute_returns_unit(
                        &tick_fn,
                        &[
                            RegisterValue::HeapMemoryAddress(HeapMemoryAddress(0)), // no return value
                            RegisterValue::HeapMemoryAddress(script.simulation_value_region.addr), // self
                        ],
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
