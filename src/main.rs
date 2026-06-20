#![allow(non_snake_case, dead_code)]

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

#[repr(C)]
struct PROCESSENTRY32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [u16; 260],
}

#[repr(C)]
struct PROCESS_MEMORY_COUNTERS {
    cb: u32,
    PageFaultCount: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
}

type BOOL = i32;
type HANDLE = isize;
type DWORD = u32;

const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
const INVALID_HANDLE_VALUE: HANDLE = -1;
const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
const PROCESS_VM_READ: DWORD = 0x0010;

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
    fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
}

#[link(name = "psapi")]
extern "system" {
    fn GetProcessMemoryInfo(
        Process: HANDLE,
        ppsmCounters: *mut PROCESS_MEMORY_COUNTERS,
        cb: DWORD,
    ) -> BOOL;
}

struct Args {
    verbose: bool,
    watch: bool,
    interval: u64,
    keywords: Vec<String>,
}

fn parse_args() -> Args {
    let mut args = Args {
        verbose: false,
        watch: false,
        interval: 3,
        keywords: Vec::new(),
    };

    let raw_args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "-v" | "--verbose" => args.verbose = true,
            "-w" | "--watch" => args.watch = true,
            "-i" | "--interval" => {
                if i + 1 < raw_args.len() {
                    i += 1;
                    if let Ok(secs) = raw_args[i].parse::<u64>() {
                        args.interval = secs;
                    }
                }
            }
            "-k" | "--keyword" => {
                if i + 1 < raw_args.len() {
                    i += 1;
                    args.keywords.push(raw_args[i].clone());
                }
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    args
}

fn print_help() {
    println!("Codex CLI Memory Analyzer");
    println!();
    println!("Usage: codex-mem-analyzer [options]");
    println!();
    println!("Options:");
    println!("  -v, --verbose          Show detailed information");
    println!("  -w, --watch            Continuous watch mode");
    println!("  -i, --interval <sec>   Refresh interval in seconds (default: 3)");
    println!("  -k, --keyword <kw>     Custom process name keyword (repeatable)");
    println!("  -h, --help             Show this help message");
}

#[derive(Clone, Debug)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    memory_kb: u64,
    virtual_memory_kb: u64,
}

#[derive(Clone)]
struct ProcessNode {
    info: ProcessInfo,
    children: Vec<ProcessNode>,
}

fn wide_string_to_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    OsString::from_wide(&wide[..len])
        .to_string_lossy()
        .into_owned()
}

fn format_memory(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.2} GB", kb as f64 / (1024.0 * 1024.0))
    } else if kb >= 1024 {
        format!("{:.2} MB", kb as f64 / 1024.0)
    } else {
        format!("{} KB", kb)
    }
}

fn enum_processes() -> Vec<ProcessInfo> {
    let mut processes = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return processes;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = wide_string_to_string(&entry.szExeFile);
                let (mem_kb, vm_kb) = get_process_memory(entry.th32ProcessID);

                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    ppid: entry.th32ParentProcessID,
                    name,
                    memory_kb: mem_kb,
                    virtual_memory_kb: vm_kb,
                });

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    processes
}

fn get_process_memory(pid: u32) -> (u64, u64) {
    unsafe {
        let access_rights = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
        let mut handle = OpenProcess(access_rights, 0, pid);

        if handle == 0 {
            handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        }

        if handle == 0 {
            handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        }

        if handle == 0 {
            return (0, 0);
        }

        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

        let mut mem_kb = 0u64;
        let mut vm_kb = 0u64;

        if GetProcessMemoryInfo(handle, &mut counters, counters.cb) != 0 {
            mem_kb = counters.WorkingSetSize as u64 / 1024;
            vm_kb = counters.PagefileUsage as u64 / 1024;
        }

        CloseHandle(handle);
        (mem_kb, vm_kb)
    }
}

fn is_codex_related(name: &str, keywords: &[String]) -> bool {
    let lower_name = name.to_lowercase();

    let default_keywords = vec![
        "codex",
        "trae",
        "npx",
        "node",
    ];

    let mut all_keywords: Vec<&str> = keywords.iter().map(|s| s.as_str()).collect();
    all_keywords.extend(default_keywords);

    for kw in &all_keywords {
        if lower_name.contains(&kw.to_lowercase()) {
            return true;
        }
    }

    false
}

fn build_process_tree(processes: &[ProcessInfo], keywords: &[String]) -> Vec<ProcessNode> {
    let process_map: HashMap<u32, ProcessInfo> = processes
        .iter()
        .map(|p| (p.pid, p.clone()))
        .collect();

    let related_pids: HashSet<u32> = processes
        .iter()
        .filter(|p| is_codex_related(&p.name, keywords))
        .map(|p| p.pid)
        .collect();

    let mut child_pids: HashSet<u32> = HashSet::new();

    for pid in &related_pids {
        if let Some(proc) = process_map.get(pid) {
            if related_pids.contains(&proc.ppid) {
                child_pids.insert(*pid);
            }
        }
    }

    let root_pids: Vec<u32> = related_pids
        .iter()
        .filter(|pid| !child_pids.contains(pid))
        .cloned()
        .collect();

    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for pid in &related_pids {
        if let Some(proc) = process_map.get(pid) {
            if related_pids.contains(&proc.ppid) {
                children_map.entry(proc.ppid).or_insert_with(Vec::new).push(*pid);
            }
        }
    }

    for (_, children) in children_map.iter_mut() {
        children.sort();
    }

    let mut sorted_roots = root_pids;
    sorted_roots.sort();

    fn build_tree(
        pid: u32,
        process_map: &HashMap<u32, ProcessInfo>,
        children_map: &HashMap<u32, Vec<u32>>,
    ) -> ProcessNode {
        let info = process_map.get(&pid).unwrap().clone();
        let mut node = ProcessNode {
            info,
            children: Vec::new(),
        };

        if let Some(children) = children_map.get(&pid) {
            for child_pid in children {
                node.children.push(build_tree(*child_pid, process_map, children_map));
            }
        }

        node
    }

    let mut root_nodes: Vec<ProcessNode> = Vec::new();
    for root_pid in &sorted_roots {
        root_nodes.push(build_tree(*root_pid, &process_map, &children_map));
    }

    root_nodes
}

fn print_tree(node: &ProcessNode, prefix: &str, is_last: bool, verbose: bool) {
    let connector = if is_last { "\u{2514}\u{2500}\u{2500} " } else { "\u{251C}\u{2500}\u{2500} " };
    let memory_str = format_memory(node.info.memory_kb);
    let vm_str = format_memory(node.info.virtual_memory_kb);

    println!(
        "{}{}{} [PID: {}] | MEM: {} | VM: {}",
        prefix, connector, node.info.name, node.info.pid, memory_str, vm_str
    );

    if verbose {
        let cmd_prefix = if is_last { "    " } else { "\u{2502}   " };
        println!(
            "{}{}  Parent PID: {}",
            prefix, cmd_prefix, node.info.ppid
        );
    }

    let child_prefix = if is_last { "    " } else { "\u{2502}   " };
    for (i, child) in node.children.iter().enumerate() {
        let is_last_child = i == node.children.len() - 1;
        print_tree(child, &(prefix.to_string() + child_prefix), is_last_child, verbose);
    }
}

fn calculate_total_memory(nodes: &[ProcessNode]) -> u64 {
    let mut total = 0;
    for node in nodes {
        total += node.info.memory_kb;
        total += calculate_total_memory(&node.children);
    }
    total
}

fn count_processes(node: &ProcessNode) -> u64 {
    let mut count = 1;
    for child in &node.children {
        count += count_processes(child);
    }
    count
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}

fn run_analysis(args: &Args) {
    let processes = enum_processes();
    let roots = build_process_tree(&processes, &args.keywords);

    if roots.is_empty() {
        println!("No Codex CLI related processes found. Make sure Codex CLI is running.");
        return;
    }

    println!();
    println!("\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
    println!("\u{2551}           Codex CLI Memory Analyzer                             \u{2551}");
    println!("\u{255A}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255D}");
    println!();

    let total_mem = calculate_total_memory(&roots);
    let total_processes: u64 = roots.iter().map(|n| count_processes(n)).sum();
    println!("Total Memory: {}", format_memory(total_mem));
    println!("Total Processes: {}", total_processes);
    println!();
    println!("Process Tree:");
    println!();

    for (i, root) in roots.iter().enumerate() {
        let is_last = i == roots.len() - 1;
        print_tree(root, "", is_last, args.verbose);
    }

    println!();
}

fn main() {
    let args = parse_args();

    if args.watch {
        loop {
            clear_screen();
            run_analysis(&args);
            println!("Press Ctrl+C to exit | Next refresh: {} seconds...", args.interval);
            std::thread::sleep(std::time::Duration::from_secs(args.interval));
        }
    } else {
        run_analysis(&args);
    }
}
