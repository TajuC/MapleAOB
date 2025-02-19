# MapleDumper

MapleDumper is a memory scanning tool designed to locate specific byte patterns within the memory of MapleStory.exe. It supports both 32-bit and 64-bit processes, reading patterns from a configuration file and saving results to a unified output file with separate sections for each architecture.

## Features

- **Multi-Architecture Support:**  
  Scan 32-bit and 64-bit versions of MapleStory using a single tool.

- **Custom Pattern Matching:**  
  Define byte patterns with wildcards (using `??` or `?`) in a configuration file.

- **Optimized Memory Scanning:**  
  Efficiently enumerates memory regions with readable protection flags and scans them for user-defined patterns.

- **Unified Result Logging:**  
  Saves found addresses into `update.txt`, maintaining separate sections for 64-bit and 32-bit results.

- **Optimized Codebase:**  
  Uses modern C++ features (e.g., C++17 `string_view`) and micro-optimizations for improved performance.

## Usage

### Prerequisites

- **Operating System:** Windows
- **Privileges:** Administrator (to access another process's memory)
- **Compiler:** C++17 compliant (e.g., Visual Studio 2017 or later)
- **Target Process:** MapleStory.exe must be running

### Configuration

1. Create a file named `patterns.txt` in the same directory as `MapleDumper.exe`.
2. Format the file with separate sections for 64-bit and 32-bit patterns. For example:

   ```plaintext
   #64BIT:
   CRC_CALL = "33 33 33 33 33 33 EB 3F 27 56"
   CRC_MAIN = "33 33 33 33 33 33 EB 3F 27 56"

   #32BIT:
   Damage = "74 38 21 45 67 89"
   GodMode = "?? ?? ?? 12 34"
Ensure that the section markers (#64BIT: and #32BIT:) are formatted exactly as shown.

Compilation
Open the project in your preferred C++ IDE (e.g., Visual Studio).
Select the appropriate build configuration (32-bit or 64-bit) based on your target.
Build the project.
Running the Tool
Run MapleDumper.exe.
When prompted, select the architecture by entering 32 or 64.
The tool will wait for MapleStory.exe to start if it isn’t already running.
It then reads the patterns from patterns.txt, scans the target process memory, and prints the results to the console.
Found addresses are appended to update.txt in the executable’s directory, with separate sections for 64-bit and 32-bit addresses.

Example Console Output
Select architecture (32/64): 64
Waiting for MapleStory.exe...
Reading patterns from E:\MapleDumper\x64\Release\patterns.txt...
Scanning memory...
Found CRC_CALL at 0x142BE3635
Found CRC_MAIN at 0x142BE362F
Found Damage at 0x6241C22
GodMode not found.
Results saved to E:\MapleDumper\x64\Release\update.txt
