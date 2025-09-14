/*
 * Copyright (c) Peter Bjorklund. All rights reserved. https://github.com/swamp/swampd
 * Licensed under the MIT License. See LICENSE in the project root for license information.
 */

pub mod scan;
mod ini;

use crate::ini::read_yini;
use crate::scan::build_single_param_function_dispatch;
use bytes::{BufMut, BytesMut};
use frag_datagram::server::address_hash;
use frag_datagram::ServerHub;
use pico_args::Arguments;
use redis::{Client, RedisError, TypedCommands};
// do not use Commands
use source_map_cache::SourceMap;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{
    env, io,
    net::UdpSocket,
    ptr, slice,
    time::{Duration, Instant},
};
use swamp::prelude::{
    compile_codegen_and_create_vm_and_run_first_time, BasicTypeKind, BasicTypeRef, CodeGenOptions, CodeGenResult,
    CompileAndCodeGenOptions, CompileAndVmResult, CompileCodeGenVmResult, CompileOptions, DebugInfo, Fp,
    GenFunctionInfo, HeapMemoryAddress, HeapMemoryRegion, HostArgs, HostFunctionCallback,
    MemoryAlignment, MemorySize, ModuleRef, Program, RunMode, RunOptions, SourceMapWrapper, TypeRef, Vm,
    VmState,
};
use swamp_runtime::{
    run_function_with_debug, CompileCodeGenAndVmOptions, CompileResult, VmOptions,
};
use swamp_vm::prelude::{AnyValue, AnyValueMut};
use swamp_vm_isa::{VecHeader, VEC_HEADER_PAYLOAD_OFFSET};
use swamp_vm_layout::LayoutCache;
use tracing::{debug, info, trace, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};
use uuid::Uuid;
use crate::ini::SwampdIni;

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

fn parse_or_warn<T>(maybe_str: Option<&str>, key: &str, kind: &str) -> T
where
    T: FromStr + Default,
    T::Err: Debug,
{
    match maybe_str {
        None => T::default(),
        Some(s) => s.parse::<T>().unwrap_or_else(|e| {
            warn!(
                "field {} malformed ({}): {:?}; defaulting to 0",
                key, kind, e
            );
            T::default()
        }),
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
    pub fn get_field_names(&self, struct_value: AnyValue) -> Vec<String> {
        trace!(hash=?struct_value.type_hash, "struct has hash");
        let basic_type = self.type_cache.universal_short_id(struct_value.type_hash);

        if let BasicTypeKind::Struct(struct_type) = &basic_type.kind {
            let mut field_names = Vec::new();
            for field in &struct_type.fields {
                let key = field.name.clone();
                field_names.push(key);
            }

            field_names
        } else {
            panic!("can not serialize. was not a struct. internal error");
        }
    }

    pub fn read_struct(&self, struct_value: AnyValue) -> Vec<(String, String)> {
        trace!(hash=?struct_value.type_hash, "struct has hash");
        let basic_type = self.type_cache.universal_short_id(struct_value.type_hash);

        if let BasicTypeKind::Struct(struct_type) = &basic_type.kind {
            let mut tuples = Vec::new();
            for field in &struct_type.fields {
                let key = field.name.clone();
                let start = field.offset.0 as usize;
                let size = field.size.0 as usize;
                trace!(key, start, size, "serializing");
                let raw_bytes_for_value = &struct_value.bytes[start..start + size];
                let value = match &field.ty.kind {
                    BasicTypeKind::U8 => raw_bytes_for_value[0].to_string(),
                    BasicTypeKind::B8 => raw_bytes_for_value[0].to_string(),
                    BasicTypeKind::U16 => {
                        let arr: [u8; 2] = raw_bytes_for_value.try_into().expect("wrong size");
                        u16::from_le_bytes(arr).to_string()
                    }
                    BasicTypeKind::S32 => {
                        let arr: [u8; 4] = raw_bytes_for_value.try_into().expect("wrong size");
                        i32::from_le_bytes(arr).to_string()
                    }
                    BasicTypeKind::U32 => {
                        let arr: [u8; 4] = raw_bytes_for_value.try_into().expect("wrong size");
                        u32::from_le_bytes(arr).to_string()
                    }
                    BasicTypeKind::Fixed32 => {
                        let arr: [u8; 4] = raw_bytes_for_value.try_into().expect("wrong size");
                        let x = i32::from_le_bytes(arr);
                        Fp::from_raw(x).to_string()
                    }
                    BasicTypeKind::StringStorage { .. } => {
                        let vec_header = raw_bytes_for_value.as_ptr() as *const VecHeader;
                        unsafe {
                            let byte_length = (*vec_header).element_count;
                            let payload_const_ptr = raw_bytes_for_value
                                .as_ptr()
                                .add(VEC_HEADER_PAYLOAD_OFFSET.0 as usize);
                            let raw_slice =
                                std::slice::from_raw_parts(payload_const_ptr, byte_length as usize);
                            String::from_utf8(raw_slice.to_vec()).unwrap()
                        }
                    }
                    _ => panic!("can not serialize"),
                };
                tuples.push((key, value));
            }

            tuples
        } else {
            panic!("can not serialize. was not a struct. internal error");
        }
    }

    pub fn write_struct(&self, struct_value_mut: AnyValueMut, hashmap: HashMap<String, String>) {
        let basic_type = self
            .type_cache
            .universal_short_id(struct_value_mut.type_hash);

        if let BasicTypeKind::Struct(struct_type) = &basic_type.kind {
            for field in &struct_type.fields {
                let key = field.name.clone();
                let s_opt: Option<&str> = hashmap.get(key.as_str()).map(String::as_str);
                let start = field.offset.0 as usize;
                let size = field.size.0 as usize;
                trace!(key, start, size, "deserializing");

                let dst: &mut [u8] = unsafe {
                    let p = struct_value_mut.data_ptr.add(start);
                    slice::from_raw_parts_mut(p, size)
                };

                match &field.ty.kind {
                    BasicTypeKind::U8 => {
                        let v: u8 = parse_or_warn(s_opt, &key, "u8");
                        dst[0] = v;
                    }
                    BasicTypeKind::B8 => {
                        let v: u8 = parse_or_warn(s_opt, &key, "u8");
                        dst[0] = v as u8;
                    }
                    BasicTypeKind::U16 => {
                        let v: u16 = parse_or_warn(s_opt, &key, "u16");
                        dst.copy_from_slice(&v.to_le_bytes());
                    }
                    BasicTypeKind::S32 => {
                        let v: i32 = parse_or_warn(s_opt, &key, "i32");
                        dst.copy_from_slice(&v.to_le_bytes());
                    }
                    BasicTypeKind::U32 => {
                        let v: u32 = parse_or_warn(s_opt, &key, "u32");
                        dst.copy_from_slice(&v.to_le_bytes());
                    }
                    BasicTypeKind::Fixed32 => {
                        let v: f32 = parse_or_warn(s_opt, &key, "f32");
                        let converted = Fp::from(v);
                        dst.copy_from_slice(&converted.inner().to_le_bytes());
                    }
                    BasicTypeKind::StringStorage {
                        element_type: _,
                        char: _,
                        capacity: _,
                    } => {
                        let v: &str = s_opt.unwrap_or_default();
                        let string_bytes = v.as_bytes();
                        unsafe {
                            let vec_header = dst.as_ptr() as *mut VecHeader;
                            (*vec_header).element_count = string_bytes.len() as u16;
                            let payload_ptr =
                                dst.as_mut_ptr().add(VEC_HEADER_PAYLOAD_OFFSET.0 as usize);
                            assert!(
                                (*vec_header).capacity as usize >= string_bytes.len(),
                                "not enough capacity"
                            );
                            ptr::copy_nonoverlapping(
                                string_bytes.as_ptr(),
                                payload_ptr,
                                string_bytes.len(),
                            );
                        }
                    }
                    _ => panic!("can not deserialize"),
                };
            }
        } else {
            panic!("was not struct. internal error");
        }
    }
    pub fn db_set(&mut self, args: HostArgs) {
        // ignore self at 1
        let key_string = args.string(2);
        let struct_value = args.any(3);
        let tuples = self.read_struct(struct_value);
        trace!(key_string, ?tuples, "writing tuples");
        self.client.hset_multiple(key_string, &tuples).unwrap()
    }

    pub fn db_delete(&mut self, args: HostArgs) {
        // ignore self at 1
        let key_string = args.string(2);
        self.client.del(key_string).unwrap();
    }

    // external 505 fn lpush(mut self, key: String, vec: String)
    pub fn db_lpush(&mut self, args: HostArgs) {
        let key_string = args.string(2);
        let value_string = args.string(3);

        self.client
            .lpush(key_string, &[value_string])
            .expect("db_lpush failed");
    }

    // external 506 fn rpush(mut self, key: String, vec: String)
    pub fn db_rpush(&mut self, args: HostArgs) {
        let key_string = args.string(2);
        let value_string = args.string(3);

        self.client
            .rpush(key_string, &[value_string])
            .expect("db_rpush failed");
    }

    // external 507 fn lpop(mut self, key: String) -> String
    pub fn db_lpop(&mut self, mut args: HostArgs) {
        let key_string = args.string(2);

        let values: Vec<String> = self
            .client
            .lpop(key_string, Some(NonZeroUsize::try_from(1usize).unwrap()))
            .expect("db_lpop failed");
        let single = values[0].as_bytes();
        args.write_to_vector_bulk(0, single);
    }

    // external 509 fn rpop(mut self, key: String) -> String
    pub fn db_rpop(&mut self, mut args: HostArgs) {
        let key_string = args.string(2);

        let values: Vec<String> = self
            .client
            .rpop(key_string, Some(NonZeroUsize::try_from(1usize).unwrap()))
            .expect("db_rpop failed");
        let single = values[0].as_bytes();
        args.write_to_vector_bulk(0, single);
    }

    // external 510 fn rpoplpush(mut self, source: String, destination: String)
    pub fn db_rpoplpush(&mut self, args: HostArgs) {
        let source_list = args.string(2);
        let destination_list = args.string(3);

        self.client
            .rpoplpush(source_list, destination_list)
            .expect("TODO: panic message");
    }

    //external 510 fn lset(mut self, key: String, index: Int, data: String)
    pub fn db_lset(&mut self, args: HostArgs) {
        let key = args.string(2);
        let index = args.register_i32(3);
        let value = args.string(4);

        self.client
            .lset(key, index as isize, value)
            .expect("TODO: panic message");
    }

    // external 511 fn llen(mut self, key: String) -> Int
    pub fn db_llen(&mut self, mut args: HostArgs) {
        let key = args.string(2);

        let length = self.client.llen(key).expect("TODO: panic message");

        args.set_register(0, length as u32);
    }

    pub fn db_hmgetset(&mut self, args: HostArgs) {
        let key_string = args.string(2);
        let struct_value_mut = args.any_mut(3);
        let struct_value = args.any(3);

        let tuples = self.read_struct(struct_value);
        let field_names: Vec<String> = tuples
            .iter()
            .map(|(first, _second)| first.clone())
            .collect();

        let mut con = self.client.get_connection().unwrap();

        let old_vals: Vec<Option<String>> = redis::pipe()
            .atomic()
            .hmget(key_string, field_names.clone())
            .hset_multiple(key_string, &tuples)
            .ignore()
            .query(&mut con)
            .expect("hmgetset failed");

        let old_map: HashMap<String, String> = field_names
            .into_iter()
            .zip(old_vals.into_iter())
            .filter_map(|(field, opt)| opt.map(|val| (field.to_string(), val)))
            .collect();

        self.write_struct(struct_value_mut, old_map);
    }

    pub fn db_get(&mut self, args: HostArgs) {
        let key_string = args.string(2);
        let struct_value_mut = args.any_mut(3);
        trace!(hash=?struct_value_mut.type_hash, "struct has hash");

        let hashmap = self.client.hgetall(key_string).unwrap();
        self.write_struct(struct_value_mut, hashmap);
    }

    pub fn db_get_int(&mut self, mut args: HostArgs) {
        let key_string = args.string(2);
        trace!(key_string, "trying to get int");
        let int_value = self.client.get_int(key_string).unwrap_or(None).unwrap_or(0) as u32;
        args.set_register(0, int_value)
    }

    pub fn db_set_int(&mut self, mut args: HostArgs) {
        let key_string = args.string(2);
        let val = args.register_i32(3);

        trace!(key_string, val, "trying to set int");
        self.client.set(key_string, val.to_string()).unwrap();
    }

    pub fn db_incr(&mut self, mut args: HostArgs) {
        let key_string = args.string(2);
        debug!(key_string, "db_incr");
        let new_value = self.client.incr(key_string, 1).expect("incr failed");
        args.set_register(0, new_value as u32);
    }
}

struct SwampDaemonCallback<'a> {
    server_hub: &'a mut ServerHub,
    db_api: DbApi<'a>,
    response: &'a UdpResponse<'a>,
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
        trace!(len=datagram.len(), ?udp_response.sock_addr, "bytes sent to peer (reply)");
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
            51 => {
                let id = Uuid::new_v4();
                let bytes = id.as_bytes();
                args.write_to_vector_bulk(0, bytes);
            }
            500 => {} //self.db_api.db_new(args),
            501 => self.db_api.db_set(args),
            502 => self.db_api.db_get(args),
            503 => self.db_api.db_incr(args),
            504 => self.db_api.db_hmgetset(args),
            505 => self.db_api.db_lpush(args),
            506 => self.db_api.db_rpush(args),
            507 => self.db_api.db_lpop(args),
            508 => self.db_api.db_rpop(args),
            509 => self.db_api.db_rpoplpush(args),
            510 => self.db_api.db_lset(args),
            511 => self.db_api.db_llen(args),
            512 => todo!(), // lrange
            513 => self.db_api.db_delete(args),
            514 => self.db_api.db_get_int(args),
            515 => self.db_api.db_set_int(args),
            _ => panic!("unknown {}", args.function_id),
        }
    }
}

struct TimeoutDaemonCallback<'a> {
    db_api: DbApi<'a>,
}

impl<'a> TimeoutDaemonCallback<'a> {}

impl HostFunctionCallback for TimeoutDaemonCallback<'_> {
    fn dispatch_host_call(&mut self, mut args: HostArgs) {
        match args.function_id {
            1 => swamp_std::print::print_fn(args),
            10 => {}
            50 => {
                // true_random()
                let mut data = [0u8; 4];
                getrandom::fill(&mut data).unwrap();
                let random_int = u32::from_le_bytes(data);
                args.set_register(0, random_int)
            }
            51 => {
                let id = Uuid::new_v4();
                let bytes = id.as_bytes();
                assert_eq!(bytes.len(), 16, "must be v4");
                args.write_to_vector_bulk(0, bytes);
            }
            501 => self.db_api.db_set(args),
            502 => self.db_api.db_get(args),
            503 => self.db_api.db_incr(args),
            504 => self.db_api.db_hmgetset(args),
            505 => self.db_api.db_lpush(args),
            506 => self.db_api.db_rpush(args),
            507 => self.db_api.db_lpop(args),
            508 => self.db_api.db_rpop(args),
            509 => self.db_api.db_rpoplpush(args),
            510 => self.db_api.db_lset(args),
            511 => self.db_api.db_llen(args),
            512 => todo!(), // lrange
            513 => self.db_api.db_delete(args),
            514 => self.db_api.db_get_int(args),
            515 => self.db_api.db_set_int(args),
            _ => panic!("unknown {}", args.function_id),

            /*
                        external 505 fn lpush(mut self, key: String, value: String) // TODO: should support [String] for values
            external 506 fn rpush(mut self, key: String, value: String) // TODO: should support [String] for values
            external 507 fn lpop(mut self, key: String) -> String
            external 508 fn rpop(mut self, key: String) -> String
            external 509 fn rpoplpush(mut self, source: String, destination: String)
            external 510 fn lset(mut self, key: String, index: Int, data: String)
            external 511 fn llen(mut self, key: String) -> Int
            external 512 fn lrange(mut self, key: String, start: Int, stop: Int) -> [String]
                     */
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
        show_instructions: bool,
    ) {
        debug!(name=func.internal_function_definition.assigned_name, a=?registers[0], "executing create func");
        let mut standard_callback = InitDaemonCallback {};

        self.execute_create_func_with_callback(
            func,
            registers,
            &mut standard_callback,
            source_map_wrapper,
            show_instructions,
        );
    }

    pub fn execute_create_func_with_callback(
        &mut self,
        func: &GenFunctionInfo,
        registers: &[RegisterValue],
        host_callback: &mut dyn HostFunctionCallback,
        source_map_wrapper: SourceMapWrapper,
        show_instructions: bool,
    ) {
        debug!(name=func.internal_function_definition.assigned_name, a=?registers[0], "executing create func with callback");

        Self::execute_returns_unit(
            func,
            registers,
            host_callback,
            &mut self.vm,
            &self.code_gen.debug_info,
            source_map_wrapper,
            show_instructions,
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
        show_instructions: bool,
    ) {
        if vm.state != VmState::Normal {
            return;
        }
        let run_options = RunOptions {
            debug_stats_enabled: show_instructions,
            debug_opcodes_enabled: show_instructions,
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

        run_function_with_debug(vm, &func.ip_range, callback, &run_options);

        //vm.state == VmState::Normal;
    }
}

fn compile_and_create_vm(
    source_map: &mut SourceMap,
    settings: &SwampdIni,
    show_assembly: bool,
) -> Result<CompileCodeGenVmResult, Error> {
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
            allow_unsafe: false,
        },
        code_gen_options: CodeGenOptions {
            show_disasm: show_assembly,
            disasm_filter: None,
            show_debug: false,
            show_types: false,
            ignore_host_call: false,
        },
        skip_codegen: false,
        run_mode: RunMode::Deployed,
    };

    let compile_codegen_and_vm_options = CompileCodeGenAndVmOptions {
        vm_options: VmOptions {
            stack_size: settings.vm.stack_size,
            heap_size: settings.vm.heap_size,
        },
        codegen: compile_and_codegen,
    };

    //let should_show_information = compile_and_codegen.compile_options.show_information;

    let program = compile_codegen_and_create_vm_and_run_first_time(
        source_map,
        &scripts_crate_path,
        compile_codegen_and_vm_options,
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

fn create_script_server<'a>(
    script: &'a mut Script,
    lookup: SourceMapWrapper<'a>,
    show_instructions: bool,
) -> (TypeRef, BasicTypeRef) {
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
        show_instructions,
    );

    script.simulation_value_region = simulation_value_region;

    (
        simulation_new_fn
            .internal_function_definition
            .signature
            .return_type
            .clone(),
        simulation_new_fn.return_type.clone(),
    )
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

    let password = env::var("KEYDB_PASSWORD").ok();

    let db_host: Option<String> = args.opt_value_from_str(["-d", "--db_host"])?;
    let redis_host = if let Some(db_host) = db_host {
        db_host
    } else {
        "127.0.0.1:6379".to_string()
    };
    println!("redis host: {redis_host}");

    let prefix = match password.as_deref() {
        None => {
            ""
        }
        Some(password) => {
            &format!(":{}@", urlencoding::encode(password))
        }
    };

    let complete_redis_url = format!("redis://{}{}", prefix, redis_host);

    let mut client = redis::Client::open(complete_redis_url)?;
    let timeout: usize = match args.opt_value_from_str::<_, usize>("--timeout") {
        Ok(Some(n)) => n,
        Ok(None) => 2,
        Err(e) => {
            eprintln!("error: invalid value for `--timeout`: {e}\n");
            print_usage();
            return Err(Error::Other("invalid value for timeout".parse().unwrap()));
        }
    };
    /*
    let mut con: Connection = client.get_connection().inspect_err(|err| {
        eprintln!("error: please start keydb. example: keydb-server /opt/homebrew/etc/keydb.conf")
    })?;

    // TODO: Remove this redis test
    con.set("foo", "bar")?;
    let val: Option<String> = con.get("foo")?;

     */

    let chdir: Option<PathBuf> = args.opt_value_from_str(["-C", "--chdir"])?;
    if let Some(dir) = chdir {
        env::set_current_dir(&dir)
            .map_err(|e| Error::Other(format!("failed to chdir to {dir:?}: {e}")))?;
    }

    let port = args
        .opt_value_from_str(["-p", "--port"])?
        .unwrap_or(DEFAULT_PORT);

    /*
    let data_dir: PathBuf = args
        .opt_value_from_str(["-d", "--data-dir"])?
        .unwrap_or_else(|| DEFAULT_DATA_DIR.into());

     */

    let scripts_dir: PathBuf = args
        .opt_value_from_str(["-s", "--scripts-dir"])?
        .unwrap_or_else(|| DEFAULT_SCRIPTS_DIR.into());

    let show_assembly = args.contains(["-a", "--show-assembly"]);
    let show_instructions = args.contains(["-i", "--show-instructions"]);

    let _ = args.finish();

    println!("start listening on port: {port}");

    let socket = UdpSocket::bind(format!("0.0.0.0:{port}"))?;

    socket.set_read_timeout(Some(Duration::from_secs(timeout as u64)))?;

    let mut buf = [0u8; 1500];
    let mut last_time = Instant::now();

    let mut source_map = swamp_compile::create_source_map(Path::new("packages"), &scripts_dir)?;

    let full_yini_path = scripts_dir.join("swampd.yini");

    let yini = read_yini(&full_yini_path);

    debug!("vm stack: {} heap: {}", human_memsize::human_size(yini.vm.stack_size as u64), human_memsize::human_size(yini.vm.heap_size as u64), );

    let vm_result = compile_and_create_vm(&mut source_map, &yini, show_assembly)?;

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

    let (server_type, server_basic_type) =
        create_script_server(&mut script, wrapper, show_instructions);

    let tick_fn = do_get_tick(&mut script, &server_type).clone();

    let on_connected_fn = script.get_impl_func(&server_type, "on_connected").clone();
    let on_disconnected_fn = script
        .get_impl_func(&server_type, "on_disconnected")
        .clone();

    let dispatch_map = build_single_param_function_dispatch(&script.code_gen, &server_basic_type);

    let incoming_param_mem_region = script
        .vm
        .memory_mut()
        .alloc_before_stack(&MemorySize(32768), &MemoryAlignment::U64);

    let mut receiver_hub = frag_datagram::ServerHub::new(10, 20, 2);

    /*
    for (index, basic_type) in &script.code_gen.layout_cache.universal_short_id_to_layout {
        info!(index, %basic_type, "types");
    }

     */

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

                if let Some((connection_id, payload, responses, is_new_connection)) =
                    receiver_hub.receive(&buf[0..len], addr_hash)
                {
                    for response in responses {
                        let _ = socket.send_to(&response, peer);
                    }
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
                            show_instructions,
                        );
                    }

                    if !payload.is_empty() {
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
                                    show_instructions,
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
                    }
                } else {
                }
            }

            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                let since = last_time.elapsed();
                if since >= Duration::from_secs(1) {
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
                                show_instructions,
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
                        show_instructions,
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
