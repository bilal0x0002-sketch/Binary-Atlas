"""
Output Formatter Module - Centralized console output management.

Encapsulates all output_console.print() calls from main analysis workflow.
Provides semantic methods for displaying analysis results with consistent formatting.

Usage:
    from src.utils.output_formatter import OutputFormatter
    
    formatter = OutputFormatter(output_console)
    formatter.print_header("Title")
    formatter.print_file_identification(path, file_hashes, imphash)
"""

from src.utils.colors import C


class OutputFormatter:
    """Centralized output formatting for analysis results."""
    
    def __init__(self, output_console):
        """
        Initialize formatter with output console.
        
        Args:
            output_console: Console object (or DualConsoleWrapper) for output
        """
        self.console = output_console
    
    # ==================== HEADERS & SECTIONS ====================
    
    def print_subheader(self, title):
        """Print a subsection header."""
        self.console.print(f"{C.HEADER}{title}{C.HEADER_END}")
    
    def print_section_divider(self):
        """Print a blank line for spacing."""
        self.console.print()
    
    # ==================== WELCOME & FILE INFO ====================
    
    def print_welcome(self, path):
        """Print welcome message with file path."""
        self.console.print(f"\n{C.HEADER}=== PE Malware Triage Tool ==={C.HEADER_END}")
        self.console.print(f"{C.LABEL}File:{C.LABEL_END} {path}\n")
    
    def print_whitelist_note(self, note):
        """Print whitelist/known binary note."""
        self.console.print(f"{C.SUCCESS}{note}{C.SUCCESS_END}\n")
    
    def print_file_identification(self, path, file_hashes, imphash, no_hash_mode=False):
        """
        Print file identification section (MD5, SHA256, ImpHash).
        
        Args:
            path: File path
            file_hashes: Dict with MD5/SHA256 keys
            imphash: Import hash string
            no_hash_mode: Boolean if hash calculation was disabled
        """
        self.print_subheader("File Identification")
        
        if no_hash_mode:
            self.console.print(f"{C.SECONDARY}Hash calculation disabled (--no-hash){C.SECONDARY_END}")
        else:
            if file_hashes and 'error' not in file_hashes:
                self.console.print(f"{C.LABEL}MD5:{C.LABEL_END} {file_hashes.get('MD5', 'N/A')}")
                self.console.print(f"{C.LABEL}SHA256:{C.LABEL_END} {file_hashes.get('SHA256', 'N/A')}")
        
        self.console.print(f"{C.LABEL}ImpHash:{C.LABEL_END} {imphash}\n")
    
    def print_privilege_context(self, subsystem_info, manifest_info):
        """
        Print privilege and execution context information.
        
        Args:
            subsystem_info: Dict with subsystem details
            manifest_info: Dict with manifest details
        """
        self.print_subheader("Privilege & Execution Context")
        self.console.print(f"{C.LABEL}Subsystem:{C.LABEL_END} {subsystem_info['subsystem_name']} ({subsystem_info['subsystem_description']})")
        self.console.print(f"{C.LABEL}Privilege Context:{C.LABEL_END} {subsystem_info['privilege_context']}")
        
        if manifest_info['has_manifest']:
            self.console.print(f"{C.LABEL}Execution Level:{C.LABEL_END} {manifest_info['execution_level']}")
            if manifest_info['requires_admin']:
                self.console.print(f"{C.ERROR}[!] REQUIRES ADMINISTRATOR PRIVILEGES{C.ERROR_END}")
            if manifest_info['ui_access']:
                self.console.print(f"{C.ERROR}[!] UI ACCESS ENABLED{C.ERROR_END}")
        else:
            self.console.print(f"{C.LABEL}Execution Level:{C.LABEL_END} NO MANIFEST (defaults to asInvoker)")
        
        self.print_section_divider()
    
    def print_verbose_mode(self):
        """Print verbose mode indicator."""
        self.console.print(f"{C.SECONDARY}Verbose mode enabled{C.SECONDARY_END}\n")
    
    # ==================== MODULE EXECUTION TIMING ====================
    
    def print_module_timing(self, module_name, elapsed_time):
        """Print module execution timing."""
        self.console.print(f"{C.SECONDARY}[OK] {module_name}: {elapsed_time:.2f}s{C.SECONDARY_END}")
    
    # ==================== THREAT ASSESSMENT ====================
    
    def print_threat_level(self, risk_level, risk_desc):
        """
        Print overall threat level and assessment.
        
        Args:
            risk_level: Formatted risk level string (e.g., "[bold red]CRITICAL[/bold red]")
            risk_desc: Risk description text
        """
        self.console.print(f"{risk_level}")
        self.console.print(f"Assessment: {risk_desc}")
    

    

    
    def print_summary_findings(self, is_packed, packer_detail, has_c2, c2_detail,
                               has_persistence, persistence_detail, has_anti_analysis,
                               complexity_score, complexity, complexity_color_markup, 
                               complexity_color_end):
        """
        Print summary of key findings.
        
        Args:
            is_packed: Boolean if file is packed
            packer_detail: Packer details string
            has_c2: Boolean if C2 detected
            c2_detail: C2 details string
            has_persistence: Boolean if persistence detected
            persistence_detail: Persistence details string
            has_anti_analysis: Boolean if anti-analysis detected
            complexity_score: Complexity score (0-6)
            complexity: Complexity level string
            complexity_color_markup: Color markup for complexity
            complexity_color_end: Color end tag for complexity
        """
        self.console.print(f"Packed:                {('[+] YES' if is_packed else '[-] NO'):25} {packer_detail}")
        self.console.print(f"C2/Communication:      {('[+] YES' if has_c2 else '[-] NO'):25} {c2_detail}")
        self.console.print(f"Persistence:           {('[+] YES' if has_persistence else '[-] NO'):25} {persistence_detail}")
        self.console.print(f"Anti-Analysis/Evasion: {('[+] YES' if has_anti_analysis else '[-] NO'):25} (anti-debug, anti-VM, timing checks)")
        self.console.print(f"{complexity_color_markup}Malware Complexity:    {complexity}{complexity_color_end} ({complexity_score}/6 indicators)")
        self.print_section_divider()
    
    def print_recommendation(self, recommendation, rec_detail):
        """
        Print final recommendation.
        
        Args:
            recommendation: Formatted recommendation string
            rec_detail: Recommendation detail text
        """
        # Recommendation output disabled
        pass
    
    def print_completion(self):
        """Print analysis completion message."""
        self.console.print(f"\n{C.SECONDARY}Analysis completed successfully{C.SECONDARY_END}\n")
