# skbreaker

**skbreaker** is an IDAPython plugin that automatically detects, decrypts, and cleans up strings encrypted with the [skCrypter](https://github.com/skadro-official/skCrypter) library. Instead of leaving behind bulky decryption routines in your disassembly, skbreaker patches the encrypted data with the cleartext string and removes the "decryption junk" from referencing functions so you can see the final result directly.

(This readme was mainly wrote by AI)

## Overview

skCrypter is a compile-time string encryption library that encrypts strings by XOR‑ing each character with a value derived from two key values (typically extracted from the compile-time `__TIME__` macro). At runtime, the decryption routine decrypts these strings on the fly.  
**skbreaker** automates this process by:

- **Scanning** a specified data segment (by default `.rdata`) for candidate encrypted strings.
- **Decrypting** each candidate using the formula:

  ```
  decrypted[i] = encrypted[i] XOR ( key1 + ( i mod (1+key2) ) )
  ```
  
- **Filtering** candidates to identify the genuine encrypted string(s)—in our example, those that contain the phrase `"This string is encrypted."` (in this example, modify it to your expected strings).
- **Patching** the encrypted data so that the decrypted, cleartext string (plus a null terminator) is permanently in place.
- **Auto-Cleanup:**  
  For every function that references the candidate, skbreaker automatically scans for the decryption loop (using a simple heuristic) and patches out the decryption junk by replacing the identified block with NOP instructions. This provides a clean and concise disassembly or decompilation view.

## How It Works

1. **Key Input and Mode Selection:**  
   When launched (via hotkey `Ctrl+Shift+K` or from the Plugins menu), skbreaker prompts you for two keys (default: 52 and 54). It also offers a brute-force mode where it tries all key pairs within the ASCII digit range (48-57) for each candidate.

2. **Segment Scanning:**  
   The plugin asks you for the name of the segment to scan (default is `.rdata`). It then iterates over every byte in that segment, attempting to decrypt substrings using the skCrypter XOR formula.

3. **Candidate Filtering:**  
   Using a heuristic check (by default, verifying that the candidate contains `"This string is encrypted."`  (in this example, modify it to your expected strings)), non-genuine or junk candidates are discarded. You can modify the filtering logic in the `is_real_string()` function if your encrypted strings differ.

4. **Patching Decrypted Data:**  
   For every genuine candidate, skbreaker patches the corresponding bytes in the segment with the decrypted string (plus a null terminator). This means that the cleartext is permanently in place.

5. **Auto-Cleanup of Decryption Junk:**  
   skbreaker automatically locates the decryption loop within each function that references the encrypted string. It does so by scanning for a CMP instruction that compares an immediate value (typically `26`) and then finds the subsequent CALL instruction (which usually corresponds to the final decryption function, such as `printf`). The plugin then NOPs out all instructions between these two points to remove the decryption junk, leaving a clean view of the final functionality.

## Installation

### Requirements

- IDA Pro with IDAPython support

### Steps

1. **Copy the Plugin File:**  
   Place the plugin file (e.g. `skbreaker.py`) into your IDA plugins folder:
   - **Windows:**  
     `C:\Program Files\IDA Pro <version>\plugins`
   - **Linux/macOS:**  
     `~/.idapro/plugins` or the appropriate plugins directory in your IDA installation.

2. **Restart IDA Pro:**  
   Restart IDA so that the plugin loads automatically.

## Usage

1. **Launch the Plugin:**  
   Open a binary in IDA Pro that uses skCrypter for string encryption and invoke **skbreaker** via the Plugins menu or with the hotkey `Ctrl+Shift+K`.

2. **Provide Key Information:**  
   When prompted, enter the decryption keys (default values 52 and 54). Optionally, enable brute-force mode to try multiple key combinations.

3. **Specify the Segment:**  
   Enter the segment name to scan (default is `.rdata`).

4. **Automatic Scanning and Patching:**  
   - The plugin scans the specified segment for encrypted strings.
   - Genuine candidates (those containing `"This string is encrypted."`) have their data patched to the cleartext.
   - All functions that reference the candidate have their decryption loops automatically detected and patched (NOPed) to remove the decryption junk.

After running, your disassembly/decompiled view will reflect the final, decrypted strings without the clutter of runtime decryption code.

## Customization

If the heuristics do not match your specific binary, you can modify:
- **Decryption Filtering:** Edit the `is_real_string()` function to adjust which decrypted strings are considered genuine.
- **Auto-Cleanup Heuristic:** Tailor the logic in the auto-patching function to better match your binary's decryption loop signature.

## Disclaimer

This plugin is provided "as is" without any warranty. Use it at your own risk. The auto-detection and patching routines rely on heuristics that may need adjustment for different binaries.

Enjoy using **skbreaker** for streamlined analysis of skCrypter-encrypted strings!
