import idaapi
import ida_bytes
import ida_segment
import ida_kernwin
import idautils
import ida_nalt
import idc

###############################
# Helper functions
###############################
def is_printable(b):
    """
    Return True if a byte (0-255) is a printable ASCII character or one of
    a few allowed whitespace/control characters.
    """
    return (32 <= b < 127) or (b in (9, 10, 13))

def try_decrypt_at(ea, seg_end, key1, key2, max_length=256):
    """
    Try to decrypt an encrypted string at address 'ea' using the skCrypter formula:
    
        decrypted[i] = encrypted[i] XOR ( key1 + (i mod (1+key2)) )
    
    Decryption stops when a null byte is encountered or when a non‑printable character is found.
    
    Returns a tuple (decrypted_string, total_length) if successful or (None, 0) if decryption fails.
    """
    decrypted_chars = []
    i = 0
    while (ea + i) < seg_end and i < max_length:
        b = ida_bytes.get_byte(ea + i)
        mask = (key1 + (i % (1 + key2))) & 0xFF
        dec = b ^ mask
        if dec == 0:
            return (''.join(decrypted_chars), i + 1)
        if not is_printable(dec):
            return (None, 0)
        decrypted_chars.append(chr(dec))
        i += 1
    return (None, 0)

def is_real_string(s):
    """
    Determine if candidate string s is the real decrypted string.
    In this example we expect the candidate to at least contain:
         "This string is encrypted."
    (This check is made looser than an exact match to help catch minor formatting differences.)
    
    BE SURE TO ADJUST WITH THE STRING YOU EXPECT TO GET ON RETURN

    LEAVE THIS EMPTY AND SCAN THE OUTPUT IF YOU DON'T KNOW WHAT STRING YOU ARE EXPECTING!!!
    """
    return "This string is encrypted." in s 

def auto_patch_decryption(func, candidate_ea, dec_str):
    """
    Automatically scan inside the given function for the decryption loop
    (using a simple heuristic) and patch out those instructions with NOPs.
    
    The heuristic works as follows:
      - Look for a CMP instruction comparing against the immediate 26 (as in "v3 < 26").
      - From that point, locate the first CALL instruction (which typically is the final printf call).
      - Patch the entire block in between with NOPs.
    """
    loop_start = None
    call_addr = None

    # Scan over instructions in the function.
    for head in idautils.FuncItems(func.start_ea):
        mnem = idc.print_insn_mnem(head).lower()
        if mnem == "cmp":
            # Check if one of the operands is the immediate 26.
            op1 = idc.print_operand(head, 1)
            try:
                val = int(op1, 0)
            except Exception:
                val = None
            if val == 26:
                loop_start = idc.get_item_head(head)
                break

    if loop_start:
        # From loop_start, look for the first CALL instruction.
        for head in idautils.Heads(loop_start, func.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            if mnem == "call":
                call_addr = head
                break

    if loop_start and call_addr and loop_start < call_addr:
        # Patch every byte between loop_start and call_addr with NOP (0x90).
        for addr in range(loop_start, call_addr):
            ida_bytes.patch_byte(addr, 0x90)
        msg = ("Auto-patched decryption block in function '%s': Patched from 0x%X to 0x%X.\n" %
               (idaapi.get_func_name(func.start_ea), loop_start, call_addr))
        ida_kernwin.msg(msg)
        # Annotate the function with a comment.
        func_cmt = ida_bytes.get_func_cmt(func.start_ea, True) or ""
        new_cmt = func_cmt + "\nDecryption junk auto-removed. Candidate patched with: \"%s\"" % dec_str
        ida_bytes.set_func_cmt(func.start_ea, new_cmt, True)
    else:
        ida_kernwin.msg("Could not auto-detect decryption block in function '%s'.\n" %
                        idaapi.get_func_name(func.start_ea))

def patch_decryption_candidate(candidate_ea, dec_str, length):
    """
    Patch the candidate data in the data segment so its bytes are replaced
    with the decrypted string (plus a null terminator).
    """
    dec_bytes = dec_str.encode("ascii") + b"\x00"
    patch_len = length  # Retain the same number of bytes.
    ida_kernwin.msg("Patching candidate data at 0x%X with decrypted string...\n" % candidate_ea)
    for i in range(patch_len):
        new_byte = dec_bytes[i] if i < len(dec_bytes) else 0
        ida_bytes.patch_byte(candidate_ea + i, new_byte)
    ida_bytes.set_cmt(candidate_ea, "Patched decrypted candidate: \"%s\"" % dec_str, 0)

###############################
# Plugin Class
###############################
class SkBreakerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "SkBreaker Plugin\n\n"
    help = ("This plugin scans a chosen segment for skCrypter-encrypted strings and automatically patches them.\n"
            "It filters out junk candidates, looking for those that contain the phrase \"This string is encrypted.\".\n"
            "For each such candidate, it patches the data and auto-detects & NOPs out the decryption junk in code.\n")
    wanted_name = "SkBreaker"
    wanted_hotkey = "Ctrl-Shift-K"  # Hotkey: Ctrl+Shift+K

    def init(self):
        ida_kernwin.msg("[SkCrypter Decryptor] Plugin initialized.\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # Ask for decryption keys (default values 52 and 54).
        key1_str = ida_kernwin.ask_str("52", 0, "Enter key1 (ASCII integer; default 52 for '__TIME__[4]'): ")
        if key1_str is None:
            return
        key2_str = ida_kernwin.ask_str("54", 0, "Enter key2 (ASCII integer; default 54 for '__TIME__[7]'): ")
        if key2_str is None:
            return
        try:
            key1_input = int(key1_str)
            key2_input = int(key2_str)
        except Exception:
            ida_kernwin.msg("Invalid key values provided.\n")
            return

        # Ask if brute-force mode should be used over ASCII digits.
        brute_response = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
            "Try brute-forcing keys in range [48,57] for each candidate?\n(Y = brute force, N = use provided keys)")
        brute_mode = (brute_response == ida_kernwin.ASKBTN_YES)

        # (Auto-filtering enabled: we only want strings that appear to be real.)
        filter_junk = True

        # Ask for the segment name to scan (default: ".rdata")
        seg_name = ida_kernwin.ask_str(".rdata", 0, "Enter segment name to scan for encrypted strings: ")
        if seg_name is None:
            return
        seg = ida_segment.get_segm_by_name(seg_name)
        if seg is None:
            ida_kernwin.msg("Segment '%s' not found.\n" % seg_name)
            return

        start_ea = seg.start_ea
        end_ea = seg.end_ea
        ida_kernwin.msg("Scanning segment %s (0x%X - 0x%X) for encrypted strings...\n" % (seg_name, start_ea, end_ea))

        processed = set()     # To avoid overlapping candidates.
        found_count = 0
        real_candidates = []  # List of tuples: (candidate address, decrypted string, length)

        ea = start_ea
        while ea < end_ea:
            if ea in processed:
                ea += 1
                continue

            candidates = []
            if brute_mode:
                for k1 in range(48, 58):
                    for k2 in range(48, 58):
                        dec_str, length = try_decrypt_at(ea, end_ea, k1, k2)
                        if dec_str is not None and length >= 4:
                            candidates.append((k1, k2, dec_str, length))
            else:
                dec_str, length = try_decrypt_at(ea, end_ea, key1_input, key2_input)
                if dec_str is not None and length >= 4:
                    candidates.append((key1_input, key2_input, dec_str, length))

            if candidates:
                # Choose the candidate with the longest decrypted string.
                best = max(candidates, key=lambda x: x[3])
                k1, k2, dec_str, length = best

                # If filtering is enabled, only keep candidates that pass our check.
                if filter_junk and not is_real_string(dec_str):
                    ida_kernwin.msg("Skipping junk candidate at 0x%X: %s\n" % (ea, dec_str))
                    ea += 1
                    continue

                # Mark candidate bytes as processed.
                for addr in range(ea, ea + length):
                    processed.add(addr)
                cmt = "Decrypted skCrypter candidate (key1=%d, key2=%d): \"%s\"" % (k1, k2, dec_str)
                ida_bytes.set_cmt(ea, cmt, 0)
                ida_kernwin.msg("Found encrypted string at 0x%X: %s\n" % (ea, dec_str))
                found_count += 1

                # Save candidate if it passes the real-string test.
                if is_real_string(dec_str):
                    real_candidates.append((ea, dec_str, length))
                ea += length
            else:
                ea += 1

        ida_kernwin.msg("Scanning complete. Found %d encrypted string(s).\n" % found_count)
        if not real_candidates:
            ida_kernwin.msg("No real (filtered) encrypted string candidates found.\n")
        else:
            ida_kernwin.msg("Real candidate(s):\n")
            for cand_ea, dec_str, length in real_candidates:
                ida_kernwin.msg("  0x%X: %s\n" % (cand_ea, dec_str))
                # First patch the candidate data in the segment.
                patch_decryption_candidate(cand_ea, dec_str, length)
                # Now, for every cross-reference (each code site that uses the candidate), auto-patch the decryption junk.
                xrefs = list(idautils.XrefsTo(cand_ea))
                if not xrefs:
                    ida_kernwin.msg("No cross-references found for candidate at 0x%X. Data patched only.\n" % cand_ea)
                    continue
                for xref in xrefs:
                    frm = xref.frm
                    func = idaapi.get_func(frm)
                    if func:
                        auto_patch_decryption(func, cand_ea, dec_str)
                    else:
                        ida_kernwin.msg("No function found referencing candidate at 0x%X\n" % cand_ea)

    def term(self):
        ida_kernwin.msg("[SkCrypter Decryptor] Plugin terminated.\n")

def PLUGIN_ENTRY():
    return SkBreakerPlugin()
