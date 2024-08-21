#!/usr/bin/env python3

# David Maynor (dmaynor@gmail.com)
# X: @Dave_maynor

# MIT License
#
# Copyright (c) 2024 David Maynor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
import sys
import json
import argparse
from typing import List, Dict, Any, Set
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class Vulnerability:
    type: str
    severity: Severity
    description: str
    line: int
    column: int
    code_snippet: str

class TclASTNode:
    def __init__(self, type: str, value: str, line: int = 0, column: int = 0):
        self.type = type
        self.value = value
        self.line = line
        self.column = column

class TclParser:
    def parse(self, content: str) -> List[TclASTNode]:
        nodes = []
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                nodes.append(TclASTNode("command", line, line=i, column=1))
        return nodes

class RuleEngine:
    def __init__(self):
        self.rules: List[Dict[str, Any]] = []

    def add_rule(self, rule: Dict[str, Any]):
        self.rules.append(rule)

    def apply_rules(self, node: TclASTNode) -> List[Vulnerability]:
        vulnerabilities = []
        for rule in self.rules:
            if re.search(rule['pattern'], node.value):
                vulnerabilities.append(Vulnerability(
                    type=rule['type'],
                    severity=Severity[rule['severity']],
                    description=rule['description'],
                    line=node.line,
                    column=node.column,
                    code_snippet=node.value.strip()
                ))
        return vulnerabilities

class TclSecurityScanner:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self.get_default_config()
        self.vulnerabilities: List[Vulnerability] = []
        self.parser = TclParser()
        self.rule_engine = RuleEngine()
        self._load_rules()

    def get_default_config(self) -> Dict[str, Any]:
        return {
            "enabled_checks": ["all"],
            "severity_threshold": "LOW",
            "max_lines_per_file": 10000,
            "ignore_patterns": []
        }

    def _load_rules(self):
        default_rules = [
            {
                'type': 'weak_encryption',
                'severity': 'HIGH',
                'description': 'Weak encryption method detected',
                'pattern': r'proc\s+xor\s+|proc\s+encrypt.*xor'
            },
            {
                'type': 'insecure_random',
                'severity': 'MEDIUM',
                'description': 'Insecure random number generation detected',
                'pattern': r'expr\s+.*rand\('
            },
            {
                'type': 'directory_traversal',
                'severity': 'HIGH',
                'description': 'Potential directory traversal vulnerability detected',
                'pattern': r'open\s+\$\w+\s*(\[|\]|\{|\})?\s*(r|w|a)'
            },
            {
                'type': 'buffer_overflow',
                'severity': 'CRITICAL',
                'description': 'Potential buffer overflow vulnerability detected',
                'pattern': r'(string\s+repeat|append)\s+\$?\w+\s+\$\w+'
            },
            {
                'type': 'xss',
                'severity': 'HIGH',
                'description': 'Potential Cross-Site Scripting (XSS) vulnerability detected',
                'pattern': r'puts.*<.*>.*\$'
            },
            {
                'type': 'unsafe_eval',
                'severity': 'HIGH',
                'description': 'Unsafe use of eval detected',
                'pattern': r'\beval\s+\$'
            },
            {
                'type': 'command_injection',
                'severity': 'CRITICAL',
                'description': 'Potential command injection vulnerability detected',
                'pattern': r'exec\s+.*\$'
            },
            {
                'type': 'hardcoded_credentials',
                'severity': 'HIGH',
                'description': 'Hardcoded credentials detected',
                'pattern': r'set\s+(username|password)\s+"[^"]+"'
            },
            {
                'type': 'sql_injection',
                'severity': 'CRITICAL',
                'description': 'Potential SQL injection vulnerability detected',
                'pattern': r'(run_query|db\s+eval).*WHERE.*\$'
            },
            {
                'type': 'insecure_file_handling',
                'severity': 'MEDIUM',
                'description': 'Insecure file handling detected',
                'pattern': r'open\s+\$?\w+\s+"w"'
            },
            {
                'type': 'sensitive_data_exposure',
                'severity': 'HIGH',
                'description': 'Potential sensitive data exposure',
                'pattern': r'save_to_file.*"Sensitive Data"'
            }
        ]
        
        for rule in default_rules:
            self.rule_engine.add_rule(rule)

        if 'custom_rules' in self.config:
            for rule in self.config['custom_rules']:
                self.rule_engine.add_rule(rule)

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        with open(file_path, 'r') as file:
            content = file.read()
        
        self.vulnerabilities = []
        ast_nodes = self.parser.parse(content)
        self._perform_ast_analysis(ast_nodes)
        return self.vulnerabilities

    def _perform_ast_analysis(self, ast_nodes: List[TclASTNode]):
        for node in ast_nodes:
            self.vulnerabilities.extend(self.rule_engine.apply_rules(node))

    def generate_report(self, format: str = 'text') -> str:
        if format == 'text':
            return self._generate_text_report()
        elif format == 'json':
            return self._generate_json_report()
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def _generate_text_report(self) -> str:
        report = "Security Scan Report\n=====================\n\n"
        if not self.vulnerabilities:
            report += "No vulnerabilities detected.\n"
        else:
            for vuln in self.vulnerabilities:
                report += f"Type: {vuln.type}\n"
                report += f"Severity: {vuln.severity.name}\n"
                report += f"Description: {vuln.description}\n"
                report += f"Location: Line {vuln.line}, Column {vuln.column}\n"
                report += f"Code: {vuln.code_snippet}\n\n"
        return report

    def _generate_json_report(self) -> str:
        return json.dumps([{
            'type': v.type,
            'severity': v.severity.name,
            'description': v.description,
            'line': v.line,
            'column': v.column,
            'code_snippet': v.code_snippet
        } for v in self.vulnerabilities], indent=2)

def main():
    parser = argparse.ArgumentParser(description="Tcl Security Scanner")
    parser.add_argument('file', help='Path to the Tcl file to scan')
    parser.add_argument('--config', help='Path to configuration file', default=None)
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Report format')
    args = parser.parse_args()

    config = None
    if args.config:
        try:
            with open(args.config, 'r') as config_file:
                config = json.load(config_file)
        except FileNotFoundError:
            print(f"Warning: Config file {args.config} not found. Using default configuration.")
        except json.JSONDecodeError:
            print(f"Warning: Config file {args.config} is not valid JSON. Using default configuration.")

    scanner = TclSecurityScanner(config)
    
    try:
        vulnerabilities = scanner.scan_file(args.file)
        print(scanner.generate_report(args.format))
    except FileNotFoundError:
        print(f"Error: The file '{args.file}' does not exist.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while scanning: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()