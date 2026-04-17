"""
Main execution flow: parse arguments → discover files → analyze sequentially → report results

Usage:
    python main.py <file.exe> [--verbose] [--output DIR] [--no-hash]
    python main.py --directory ./samples --no-hash
    python main.py --glob "**/*.exe" --no-hash
"""

import sys
import os
import argparse
import glob
from rich.console import Console

from src.utils.colors import C
from src.utils.logger import init_logger
from src.utils.discovery import discover_files
from src.orchestration.coordinator import analyze_file


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="PE Malware Triage Tool",
        description="Analyze PE executables for malware indicators",
        epilog="Examples:\n  python main.py malware.exe --verbose\n  python main.py --directory ./samples\n  python main.py --glob '*.exe'"
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("file", nargs="?", help="Path to single PE file (exe, dll, sys)")
    input_group.add_argument("--directory", "-d", type=str, help="Directory containing PE files for batch processing")
    input_group.add_argument("--glob", "-g", type=str, help="Glob pattern for batch file processing (e.g., './samples/*.exe')")
    
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose/debug output")
    parser.add_argument("--output", "-o", type=str, default="output", help="Output directory for reports (default: ./output)")
    parser.add_argument("--config", "-c", type=str, help="Custom configuration file path")
    parser.add_argument("--timeout", "-t", type=int, default=300, help="Per-file analysis timeout in seconds (default: 300)")
    parser.add_argument("--no-hash", action="store_true", help="Disable file hash calculation (MD5/SHA256) for faster batch processing")
    
    args = parser.parse_args()
    
    # Validate input
    if args.file and not os.path.exists(args.file):
        parser.error(f"File not found: {args.file}")
    elif args.directory and not os.path.isdir(args.directory):
        parser.error(f"Directory not found: {args.directory}")
    elif args.glob and not glob.glob(args.glob, recursive=True):
        parser.error(f"No files matching glob pattern: {args.glob}")
    
    os.makedirs(args.output, exist_ok=True)
    if args.config and not os.path.exists(args.config):
        parser.error(f"Config file not found: {args.config}")
    
    return args


def main():
    """Main orchestration: arguments → discovery → analysis → reporting."""
    init_logger(level="INFO")
    args = parse_arguments()
    display_console = Console()
    
    os.makedirs(args.output, exist_ok=True)
    files = discover_files(args)
    
    if not files:
        display_console.print(f"{C.ERROR}[!] No files to analyze{C.ERROR_END}")
        return 1
    
    display_console.print(f"{C.CYAN}Found {len(files)} file(s) to analyze{C.END_CYAN}\n")
    
    # Single file analysis
    if len(files) == 1:
        success, message = analyze_file(files[0], args.output, args, display_console)
        if success:
            display_console.print(f"{C.SUCCESS}{message}{C.SUCCESS_END}")
            return 0
        else:
            display_console.print(f"{C.ERROR}[X] {message}{C.ERROR_END}")
            return 1
    
    # Batch processing
    display_console.print(f"{C.WARNING}Processing {len(files)} files in batch mode...{C.WARNING_END}\n")
    successful = 0
    failed = 0
    
    for idx, file_path in enumerate(files, 1):
        display_console.print(f"{C.CYAN}[{idx}/{len(files)}] {os.path.basename(file_path)}{C.END_CYAN}")
        success, message = analyze_file(file_path, args.output, args, display_console)
        
        if success:
            successful += 1
            display_console.print(f"{C.SUCCESS}  [+] OK{C.SUCCESS_END}")
        else:
            failed += 1
            display_console.print(f"{C.WARNING}  [-] {message}{C.WARNING_END}")
        display_console.print()
    
    display_console.print(f"\n{C.HEADER}=== Batch Processing Summary ==={C.HEADER_END}")
    display_console.print(f"{C.SUCCESS}Successful: {successful}{C.SUCCESS_END}")
    display_console.print(f"{C.WARNING}Failed: {failed}{C.WARNING_END}")
    display_console.print(f"{C.CYAN}Output directory: {args.output}{C.END_CYAN}")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
