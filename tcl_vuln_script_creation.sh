#!/bin/bash

# David Maynor (dmaynor@gmail.com)
# X: @dave_maynor

# MIT License
MIT_LICENSE="# MIT License
#
# Copyright (c) $(date +%Y) David Maynor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the \"Software\"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE."

# Initialize an array to keep track of all created files
declare -a created_files

# Function to print the help message
function print_help {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h      Show this help message and exit."
    echo "  -d      Delete all generated TCL scripts and dependencies."
    echo "  -c      Use Docker containerization (if Docker is installed)."
    echo ""
    echo "Author: David Maynor"
    echo "Contact: dmaynor@gmail.com"
    echo "X: @dave_maynor"
}

# Function to create a TCL script with MIT License, author info, and comments on vulnerabilities
create_tcl_script() {
    local filename=$1
    local description=$2
    local content=$3

    cat <<EOF > "$filename"
# David Maynor (dmaynor@gmail.com)
# X: @dave_maynor

$MIT_LICENSE

# Description:
# $(echo "$description" | sed 's/^/# /')

$content
EOF

    # Add the created file to the list
    created_files+=("$filename")
}

# Function to delete all generated TCL scripts and dependencies
delete_tcl_scripts() {
    for file in "${created_files[@]}"; do
        rm -f "$file"
    done
    echo "All generated TCL scripts and related files have been deleted."
}

# Function to create a mock passwd file
create_mock_passwd_file() {
    local passwd_file="passwd"
    cat <<EOF > "$passwd_file"
root:x:0:0:root:/root:/bin/bash
user:x:1000:1000:User:/home/user:/bin/bash
guest:x:1001:1001:Guest:/home/guest:/bin/sh
EOF

    # Add the passwd file to the list of created files
    created_files+=("$passwd_file")
}

# Initialize Docker usage flag
USE_DOCKER=false

# Parse command-line options
while getopts "hdc" opt; do
    case $opt in
        h)
            print_help
            exit 0
            ;;
        d)
            delete_tcl_scripts
            exit 0
            ;;
        c)
            USE_DOCKER=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            print_help
            exit 1
            ;;
    esac
done

# Check Docker availability if the -c option was used
if [ "$USE_DOCKER" = true ]; then
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker is not installed. Please install Docker to use containerization."
        exit 1
    fi
    echo "Docker is installed. Containerization will be used."
fi

# Check if SQLite is installed
if ! command -v sqlite3 &> /dev/null; then
    echo "Error: SQLite is not installed. Please install SQLite to proceed."
    exit 1
fi

# Create an SQLite database with sensitive-looking data
sqlite3 my_database.db <<EOF
DROP TABLE IF EXISTS users;
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT);
INSERT INTO users (name, password) VALUES ('admin', 'supersecret123'), ('user', 'password'), ('guest', 'guest123');
EOF

# Track the SQLite database file
created_files+=("my_database.db")

# Function to create Dockerfile
create_dockerfile() {
    cat <<EOF > Dockerfile
# Use an official Tcl runtime as a parent image
FROM tcl:8.6

# Install necessary dependencies
RUN apt-get update && apt-get install -y \\
    sqlite3 \\
    bash \\
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container
COPY . .

# Make the script executable
RUN chmod +x generate_vulnerable_tcl.sh

# Run the script when the container launches
CMD ["./generate_vulnerable_tcl.sh"]
EOF

    # Add Dockerfile to the list of created files
    created_files+=("Dockerfile")
    echo "Dockerfile has been created."
}

# Function to build and run Docker container
build_and_run_docker() {
    echo "Building Docker image..."
    docker build -t tcl-vulnerability-tester .

    echo "Running vulnerability tests in Docker container..."
    docker run --rm tcl-vulnerability-tester
}

# Create Dockerfile if using Docker
if [ "$USE_DOCKER" = true ]; then
    create_dockerfile
fi

# Create the TCL scripts

# 1. Hardcoded Credentials & Insecure File Handling
create_tcl_script "script1_hardcoded_credentials.tcl" \
"1. Hardcoded Credentials: The username and password are hardcoded into the script.
2. Insecure File Handling: The script saves sensitive data to a file in an insecure manner.
Exploitation:
- An attacker could gain unauthorized access using the hardcoded credentials.
- Sensitive data could be accessed or modified by unauthorized users due to insecure file handling." \
'
set username "admin"
set password "password123"

proc authenticate {user pass} {
    if {$user == $::username && $pass == $::password} {
        puts "Authentication successful!"
    } else {
        puts "Authentication failed!"
    }
}

proc save_to_file {filename content} {
    set file [open $filename "w"]
    puts $file $content
    close $file
}

authenticate "admin" "password123"
save_to_file "output.txt" "Sensitive Data"
'

# 2. Command Injection & SQL Injection
create_tcl_script "script2_command_injection_sql_injection.tcl" \
"1. Command Injection: The script allows arbitrary command execution via user input.
2. SQL Injection: The script is vulnerable to SQL injection by allowing unsanitized user input in SQL queries.
Exploitation:
- An attacker could execute arbitrary commands by injecting malicious input.
- SQL injection can be used to retrieve or modify database records." \
'
proc delete_file {filename} {
    exec rm -rf $filename
}

proc run_query {query} {
    exec sqlite3 my_database.db $query
}

delete_file "/tmp/test.txt; rm -rf /important/data"
run_query "SELECT * FROM users WHERE id=1 OR 1=1"
'

# 3. XSS & Unsafe eval
create_tcl_script "script3_xss_unsafe_eval.tcl" \
"1. Cross-Site Scripting (XSS): The script displays user input without proper sanitization, leading to XSS.
2. Unsafe eval: The script uses the eval command to execute user input, allowing arbitrary code execution.
Exploitation:
- An attacker could inject malicious JavaScript to be executed in the victim's browser.
- The eval function can be exploited to run arbitrary TCL commands." \
'
set user_input "<script>alert(\"Hacked!\");</script>"

proc display {text} {
    puts "<html><body>$text</body></html>"
}

proc execute_command {cmd} {
    eval $cmd
}

display $user_input
execute_command "puts [exec whoami]"
'

# 4. Directory Traversal & Buffer Overflow
create_tcl_script "script4_directory_traversal_buffer_overflow.tcl" \
"1. Directory Traversal: The script allows users to read files outside the intended directory.
2. Buffer Overflow: The script has a buffer overflow vulnerability in the string handling.
Exploitation:
- An attacker could read sensitive files like the passwd file using directory traversal.
- Buffer overflow can lead to crashes or arbitrary code execution." \
'
proc read_file {filename} {
    set file [open $filename]
    set content [read $file]
    close $file
    return $content
}

proc vulnerable {input} {
    set buffer [string repeat "A" 256]
    append buffer $input
    puts "Buffer: $buffer"
}

# Test the vulnerabilities
puts [read_file "passwd"]
vulnerable "A very long string that causes overflow..."
'

# Create a mock passwd file for the directory traversal test
create_mock_passwd_file

# 5. Weak Encryption & Insecure Random Number Generation
create_tcl_script "script5_weak_encryption_insecure_random.tcl" \
"1. Weak Encryption: The script uses a simple XOR cipher for encryption, which is easily broken.
2. Insecure Random Number Generation: The script uses a non-cryptographically secure random number generator.
Exploitation:
- The weak encryption can be easily decrypted by attackers.
- The insecure random number generator could be predicted and exploited." \
'
proc xor {s key} {
    set res ""
    set keylen [string length $key]
    for {set i 0} {$i < [string length $s]} {incr i} {
        append res [format %c [expr {[scan [string index $s $i] %c] ^ [scan [string index $key [expr {$i % $keylen}]] %c]}]]
    }
    return $res
}

proc encrypt {plaintext key} {
    return [binary encode base64 [xor $plaintext $key]]
}

proc decrypt {ciphertext key} {
    return [xor [binary decode base64 $ciphertext] $key]
}

set encrypted [encrypt "SensitiveData" "1234"]
puts "Encrypted: $encrypted"
puts "Decrypted: [decrypt $encrypted "1234"]"

set token [expr int(rand() * 10000)]
puts "Generated token: $token"
'

# Main execution logic
if [ "$USE_DOCKER" = true ]; then
    build_and_run_docker
else
    echo "Running vulnerability tests locally..."
    for script in script*.tcl; do
        echo "Running $script:"
        tclsh $script
        echo "-------------------------"
    done
fi

# Completion message
echo "All TCL scripts and necessary dependencies have been created."
if [ "$USE_DOCKER" = true ]; then
    echo "Tests were run in a Docker container."
else
    echo "Tests were run locally."
fi

# Cleanup function (optional)
cleanup() {
    echo "Cleaning up generated files..."
    for file in "${created_files[@]}"; do
        rm -f "$file"
    done
    echo "Cleanup complete."
}

# Uncomment the following line if you want automatic cleanup after running
# trap cleanup EXIT