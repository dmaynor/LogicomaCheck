# LogicomaCheck

## Overview

LogicomaCheck is an early prototype tool designed to analyze Tcl scripts for potential security vulnerabilities. It uses pattern matching and simple AST analysis to identify common security issues in Tcl code.

**Author:** David Maynor (dmaynor@gmail.com)  
**X:** @Dave_maynor

## Disclaimer

This tool is currently in an early prototype stage. It may produce false positives or miss certain vulnerabilities. Always combine automated scanning with manual code review for comprehensive security analysis.

## Features

- Detects common security vulnerabilities in Tcl scripts
- Supports both text and JSON output formats
- Configurable through custom rule sets
- Provides severity levels for detected vulnerabilities

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/dmaynor/LogicomaCheck.git
   ```
2. Navigate to the project directory:
   ```
   cd LogicomaCheck
   ```
3. Ensure you have Python 3.6+ installed.

## Usage

Run LogicomaCheck on a Tcl file:

```
python logicomacheck.py path/to/your/tcl/script.tcl
```

### Options

- `--config`: Specify a custom configuration file (JSON format)
- `--format`: Choose output format (`text` or `json`)

Example:
```
python logicomacheck.py path/to/your/tcl/script.tcl --format json
```

## Adding Custom Rules

You can add custom rules by creating a JSON configuration file. Here's an example structure:

```json
{
  "custom_rules": [
    {
      "type": "custom_vulnerability",
      "severity": "HIGH",
      "description": "Description of the custom vulnerability",
      "pattern": "regex_pattern_to_match"
    }
  ]
}
```

Then, run LogicomaCheck with your custom configuration:

```
python logicomacheck.py path/to/your/tcl/script.tcl --config your_config.json
```

## Current Vulnerability Checks

- Weak Encryption
- Insecure Random Number Generation
- Directory Traversal
- Buffer Overflow
- Cross-Site Scripting (XSS)
- Unsafe Eval Usage
- Command Injection
- Hardcoded Credentials
- SQL Injection
- Insecure File Handling
- Sensitive Data Exposure

## Contributing

As LogicomaCheck is an early prototype, contributions, suggestions, and feedback are welcome. Please feel free to open issues or submit pull requests on the [GitHub repository](https://github.com/dmaynor/LogicomaCheck).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
