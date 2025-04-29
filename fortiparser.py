#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FortiGate Parser & Diagram Generator

Parses a FortiGate CLI configuration file, generates diagrams, reports,
and optionally performs path tracing.
"""

import argparse
import re
import sys
import ipaddress
# Removed: from graphviz import Digraph (Now handled in diagram_generator)

# Import custom modules
from config_model import ConfigModel
from diagram_generator import NetworkDiagramGenerator
from utils import print_table

# --- FortiParser Class ---
# This class remains here as the core parsing logic.

class FortiParser:
    """Parses a FortiGate CLI export into a ConfigModel."""
    # More flexible regex: Allow more whitespace, handle names with spaces if quoted.
    SECTION_RE = re.compile(r'^config\s+("?.*?"?|\S+)\s*$') # Handle quoted/unquoted section names
    EDIT_RE    = re.compile(r'^\s*edit\s+(?:"([^"]+)"|(\S+))\s*$', re.IGNORECASE) # Allow leading space
    SET_RE     = re.compile(r'^\s*set\s+(\S+)\s+(.*)$') # Allow leading space, capture everything after name
    # Append/Unset commands (useful for diffing later, but maybe not primary parse)
    APPEND_RE  = re.compile(r'^\s*append\s+(\S+)\s+(.*)$')
    UNSET_RE   = re.compile(r'^\s*unset\s+(\S+)\s*$')
    NEXT_RE    = re.compile(r'^\s*next\s*$', re.IGNORECASE) # Allow leading/trailing space
    END_RE     = re.compile(r'^\s*end\s*$', re.IGNORECASE)   # Allow leading/trailing space
    VDOM_CONFIG_RE = re.compile(r'^config\s+vdom$', re.IGNORECASE) # Regex for 'config vdom'
    GLOBAL_CONFIG_RE = re.compile(r'^config\s+global$', re.IGNORECASE) # Regex for 'config global'
    # Regex for FortiOS version string (handles X.Y and X.Y.Z, various build prefixes)
    VERSION_RE = re.compile(r'^#config-version=\s*.*?(\d+)\.(\d{1,2})(?:\.(\d+))?.*?\s*(?:-?build|-?b)?\s*(\d+).*$', re.IGNORECASE)
    # --- Section Name Aliases ---
    # Map known historical/alternative section names (normalized) to current handler method names.
    # This helps maintain compatibility across different FortiOS versions.
    # Keys: Normalized section name found in config (lowercase, space/hyphen -> underscore)
    # Values: The corresponding handler method name in this class (e.g., '_handle_firewall_address')
    # Populate this map as needed based on observed FortiOS changes.
    SECTION_ALIASES = {
        # --- Examples (Uncomment and adjust based on actual version differences) ---
        # 'firewall_addr': '_handle_firewall_address',        # If 'firewall addr' was used
        # 'firewall_service': '_handle_firewall_service_custom', # If 'service' was used instead of 'service custom'
        # 'vpn_ipsec_phase1': '_handle_vpn_ipsec_phase1_interface', # If '-interface' suffix was added later
        # 'vpn_ipsec_phase2': '_handle_vpn_ipsec_phase2_interface', # If '-interface' suffix was added later
        # 'webfilter_profile': '_handle_web_filter_profile', # Common renaming pattern
        # 'application_list': '_handle_app_control',         # Application list vs app control profile
        # 'ips_sensor': '_handle_ips',                     # Sensor vs Profile? Check model.
        'switch_vlan': '_handle_system_interface',  # Older versions might have used 'config switch vlan' for L3 VLAN interfaces
                                                     # More specific handling might be needed if structure also changed.
        'log_fortianalyzer_setting': '_handle_system_fortianalyzer', # Consolidate log settings under main component
        'log_fortisandbox_setting': '_handle_system_fortisandbox',  # Consolidate log settings
        # Add more aliases here as needed
    }

    # ADDED debug flag
    def __init__(self, lines, debug=False):
        self.lines = lines
        self.i     = 0
        self.debug = debug # Store debug flag
        self.current_vdom = None # Initialize current VDOM tracking
        self.model = ConfigModel() # Instantiate the model from config_model.py
        self.model.has_vdoms = False # Initialize VDOM flag
        self.fortios_version_found = False # Track if version line was found

    # --- Helper to convert Mask to Prefix ---
    def _mask_to_prefix(self, mask_str):
        """Converts a netmask string (e.g., 255.255.255.0) to prefix length (e.g., 24)."""
        try:
            # Treat mask as an IP address and get its prefix length from binary representation
            mask_addr = ipaddress.ip_address(mask_str)
            if isinstance(mask_addr, ipaddress.IPv4Address):
                 # Calculate prefix length for IPv4 by counting set bits
                 return bin(int(mask_addr)).count('1')
            elif isinstance(mask_addr, ipaddress.IPv6Address):
                 # IPv6 uses ipaddress internal property
                 # Create a dummy network to extract prefix from mask
                 dummy_net = ipaddress.IPv6Network(f"::/%s" % mask_str, strict=False) # Use % formatting for older compatibility if needed
                 return dummy_net.prefixlen
        except ValueError:
             # Provide more specific error message
             print(f"Warning [Line ~{self.i+1}]: Invalid netmask format '{mask_str}'. Cannot convert to prefix length.", file=sys.stderr)
        return None # Indicate failure

    def parse(self):
        """Parse the config file and return a ConfigModel."""
        self.i = 0
        self.current_vdom = None # Ensure it starts as None
        self.model.has_vdoms = False # Ensure it starts as False
        self.fortios_version_found = False # Reset for parsing
        last_successful_line = 0 # Track the last line successfully processed
        if self.debug: print("*** FortiParser START ***") # DEBUG

        # --- First pass: Find FortiOS version ---
        version_search_limit = min(20, len(self.lines))
        for line_idx in range(version_search_limit):
             line = self.lines[line_idx].strip()
             m_ver = self.VERSION_RE.match(line)
             if m_ver:
                 major_str, minor_str, patch_str, build_str = m_ver.groups()
                 major = int(major_str)
                 minor = int(minor_str)
                 patch = int(patch_str) if patch_str is not None else 0
                 build = int(build_str)
                 version_str = f"v{major}.{minor}.{patch},build{build}"
                 self.model.fortios_version = version_str
                 self.model.fortios_version_details = {
                      'major': major, 'minor': minor, 'patch': patch, 'build': build
                 }
                 self.fortios_version_found = True
                 print(f"Detected FortiOS Version: {version_str}")
                 break

        if not self.fortios_version_found:
             print("Warning: Could not detect FortiOS version from config header.", file=sys.stderr)

        # --- Main Parsing Loop ---
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            original_line_index = self.i # Store index before potential skips

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                self.i += 1
                last_successful_line = self.i # Update even on skips
                if self.debug: print(f"[L{self.i}] Skipping comment/empty") # DEBUG
                continue

            # --- Top-Level Commands --- #
            m_vdom = self.VDOM_CONFIG_RE.match(line)
            m_global = self.GLOBAL_CONFIG_RE.match(line)
            m_section = self.SECTION_RE.match(line)
            m_end = self.END_RE.match(line) # Check for stray 'end' at top level

            if m_vdom:
                if self.debug: print(f"[L{original_line_index+1}] Entering VDOM config") # DEBUG
                self._handle_vdom_config()
                self.current_vdom = None # Reset VDOM context after the block
                last_successful_line = self.i
                if self.debug: print(f"[L{self.i}] Exiting VDOM config") # DEBUG
                continue

            elif m_global:
                if self.debug: print(f"[L{original_line_index+1}] Entering Global config") # DEBUG
                self.current_vdom = 'global' if self.model.has_vdoms else None
                self.i += 1 # Consume 'config global'
                # TODO: Optionally handle settings directly under 'config global' if they exist
                # Need to check if 'config global' contains only 'config' blocks or also 'set' commands
                last_successful_line = self.i
                if self.debug: print(f"[L{self.i}] Exiting Global config") # DEBUG
                continue

            elif m_section:
                # --- Regular Section Parsing --- #
                # Group 1 contains the potentially quoted section name
                raw_section_name = m_section.group(1).strip().replace('"', '') # Remove quotes
                normalized_section_name = raw_section_name.lower().replace(' ', '_').replace('-', '_')

                handler_method_name = self.SECTION_ALIASES.get(normalized_section_name)
                if not handler_method_name:
                    handler_method_name = f'_handle_{normalized_section_name}'

                handler = getattr(self, handler_method_name, None)
                if self.debug: print(f"[L{original_line_index+1}] Matched section: '{raw_section_name}' -> Handler: {handler_method_name if handler else 'Generic/None'}") # DEBUG

                if handler:
                    try:
                        handler() # Call the specific or generic handler
                        # Handler should advance self.i past the section's end
                        last_successful_line = self.i
                    except Exception as e:
                        print(f"ERROR: Handler {handler_method_name} failed processing section '{raw_section_name}' starting near line {original_line_index + 1}: {e}", file=sys.stderr)
                        print(f"Attempting to recover by skipping to next likely block start or end...", file=sys.stderr)
                        # --- Recovery Attempt --- #
                        self.i = original_line_index # Reset i to start of failed section
                        if not self._skip_to_next_block_or_end():
                             print(f"FATAL: Recovery failed. Could not find next block after error at line {original_line_index + 1}. Stopping parse.", file=sys.stderr)
                             return self.model # Return partially parsed model
                        print(f"Recovered: Skipped to line {self.i + 1}.", file=sys.stderr)
                else:
                    # No specific handler found, use generic (which also calls _read_block/_read_settings)
                    if self.debug: print(f"[L{original_line_index+1}] Using generic handler for section '{raw_section_name}'", file=sys.stderr) # DEBUG
                    try:
                        self._handle_generic_section(raw_section_name, normalized_section_name)
                        last_successful_line = self.i
                    except Exception as e:
                         print(f"ERROR: Generic handler failed processing section '{raw_section_name}' starting near line {original_line_index + 1}: {e}", file=sys.stderr)
                         print(f"Attempting to recover by skipping to next likely block start or end...", file=sys.stderr)
                         self.i = original_line_index
                         if not self._skip_to_next_block_or_end():
                              print(f"FATAL: Recovery failed. Could not find next block after error at line {original_line_index + 1}. Stopping parse.", file=sys.stderr)
                              return self.model
                         print(f"Recovered: Skipped to line {self.i + 1}.", file=sys.stderr)
                continue # Continue main loop after handling section

            elif m_end:
                # Encountered an 'end' at the top level or VDOM level inappropriately
                print(f"Warning [Line {original_line_index + 1}]: Encountered unexpected 'end' statement outside of a config block. Skipping.", file=sys.stderr)
                self.i += 1
                last_successful_line = self.i
                continue

            # --- Handle unexpected lines --- #
            else:
                # This line doesn't match any known top-level command or pattern
                print(f"Warning [Line {original_line_index + 1}]: Skipping unexpected line at top level: {line}", file=sys.stderr)
                # Simple recovery: just advance. More robust recovery could search forward.
                self.i += 1
                # Don't update last_successful_line here, as this line wasn't processed

        # --- End of Parsing --- #
        if self.i < len(self.lines):
             print(f"Warning: Parsing loop finished prematurely at line {self.i + 1}. Check for errors or unexpected EOF.", file=sys.stderr)
        elif self.i > last_successful_line:
             print(f"Warning: Parsing finished, but the last {self.i - last_successful_line} lines might not have been fully processed due to trailing unexpected content or errors.", file=sys.stderr)
        else:
             print(f"Parsing complete. Processed {last_successful_line} lines.")

        # Print detected version at the end as well
        if self.model.fortios_version:
            print(f"Detected FortiOS Version: {self.model.fortios_version}")
        else:
             print(f"Final Check: FortiOS Version not detected.")
             
        if self.debug: print("*** FortiParser END ***") # DEBUG
        return self.model

    # --- VDOM Handling Method --- 
    def _handle_vdom_config(self):
        """Handles the 'config vdom' block, including 'edit <vdom_name>' entries and their nested configs."""
        self.i += 1 # Move past 'config vdom'
        self.model.has_vdoms = True # Mark VDOMs enabled

        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            
            if self.END_RE.match(line):
                self.i += 1 # Consume 'end' for 'config vdom'
                return

            m_edit = self.EDIT_RE.match(line)
            if m_edit:
                vdom_name = m_edit.group(1) or m_edit.group(2)
                self.current_vdom = vdom_name
                self.i += 1 # Consume 'edit <vdom_name>' line
                
                if self.current_vdom not in self.model.vdoms:
                     self.model.vdoms[self.current_vdom] = ConfigModel()

                while self.i < len(self.lines):
                    inner_line = self.lines[self.i].strip()
                    
                    if self.NEXT_RE.match(inner_line):
                        self.i += 1
                        break

                    if self.END_RE.match(inner_line):
                         return

                    m_section = self.SECTION_RE.match(inner_line)
                    if m_section:
                         raw_section_name = m_section.group(1).strip()
                         normalized_section_name = raw_section_name.lower().replace(' ', '_').replace('-', '_')
                         handler_method_name = self.SECTION_ALIASES.get(normalized_section_name) or f'_handle_{normalized_section_name}'
                         handler = getattr(self, handler_method_name, None)

                         if handler:
                             try: 
                                 handler()
                             except Exception as e:
                                  print(f"ERROR: VDOM Handler {handler_method_name} failed for section '{raw_section_name}': {e}", file=sys.stderr)
                                  self._skip_block()
                         else:
                              self._handle_generic_section(raw_section_name, normalized_section_name)
                         continue
                    if not inner_line or inner_line.startswith('#'):
                         self.i += 1
                         continue
                         
                    print(f"Warning: Skipping unexpected line inside VDOM '{self.current_vdom}' entry at line {self.i+1}: {inner_line}")
                    self.i += 1 
                # End of inner loop (after 'next' or reaching 'end')
            
            elif not line or line.startswith('#'):
                 self.i += 1
                 continue
            
            else:
                print(f"Warning: Skipping unexpected line inside 'config vdom' block at line {self.i+1}: {line}")
                self.i += 1

        print("Warning: Reached end of file while inside 'config vdom' block.", file=sys.stderr)
        self.current_vdom = None # Clear context
        
    # --- Block Reading Helpers --- 
    def _skip_block(self):
        """(Deprecated - Use _skip_to_next_block_or_end) Skip lines until the matching 'end' is found. Basic version."""
        print("DEPRECATION WARNING: _skip_block() called. Use _skip_to_next_block_or_end() for better recovery.", file=sys.stderr)
        nesting_level = 1
        # self.i should be at the line *after* the failed 'config' line when this is called by old logic
        start_line = self.i
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            # Use SECTION_RE to correctly identify nested config starts
            if self.SECTION_RE.match(line):
                nesting_level += 1
            elif self.END_RE.match(line):
                nesting_level -= 1
                if nesting_level == 0:
                    self.i += 1 # Consume the final 'end'
                    print(f"_skip_block: Skipped from {start_line +1} to {self.i + 1}", file=sys.stderr)
                    return True # Successfully skipped the block
            self.i += 1
        print(f"Warning: Reached end of file while skipping block starting near line {start_line + 1}. Nesting level: {nesting_level}", file=sys.stderr)
        return False # Failed to find matching end

    def _skip_to_next_block_or_end(self):
        """Robustly skips the current block or malformed lines until the next 'config' or top-level 'end'.
        
        Assumes self.i is at the start of the problematic line/block.
        Advances self.i to the beginning of the next valid block or EOF.
        Returns True if recovery seems successful, False otherwise.
        """
        original_line_index = self.i
        nesting_level = 1 # Assume we are inside the block that failed to parse
        print(f"_skip_to_next_block_or_end: Starting recovery from line {original_line_index + 1}...", file=sys.stderr)
        
        self.i += 1 # Start searching from the next line
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()

            # Skip comments and empty lines during search
            if not line or line.startswith('#'):
                self.i += 1
                continue

            # Check for nested config start
            if self.SECTION_RE.match(line):
                 nesting_level += 1
                 print(f"_skip: Nested config found at line {self.i+1}, level -> {nesting_level}", file=sys.stderr) # DEBUG
            # Check for end command
            elif self.END_RE.match(line):
                 nesting_level -= 1
                 print(f"_skip: End found at line {self.i+1}, level -> {nesting_level}", file=sys.stderr) # DEBUG
                 if nesting_level == 0:
                     # Found the end of the block we were trying to skip
                     self.i += 1 # Consume the 'end'
                     print(f"_skip_to_next_block_or_end: Found matching 'end' at line {self.i}. Resuming parse.", file=sys.stderr)
                     return True
                 elif nesting_level < 0:
                      # Too many ends - indicates a malformed structure earlier
                      print(f"Warning [Line {self.i+1}]: Encountered unexpected 'end' during skip recovery (nesting level {nesting_level}). Possible config corruption.", file=sys.stderr)
                      # Treat this as potentially the end of the faulty block anyway?
                      self.i += 1
                      return True # Attempt to continue

            # If nesting level is back to 0 (or less), look for the *next* config block start
            if nesting_level <= 0:
                 if self.SECTION_RE.match(line) or self.VDOM_CONFIG_RE.match(line) or self.GLOBAL_CONFIG_RE.match(line):
                     print(f"_skip_to_next_block_or_end: Found next config block at line {self.i + 1}. Resuming parse before this line.", file=sys.stderr)
                     # Do *not* consume this line, the main loop should handle it
                     return True

            # Keep searching
            self.i += 1

        # Reached EOF
        print(f"Warning: Reached end of file during skip recovery starting from line {original_line_index + 1}. Final nesting level: {nesting_level}", file=sys.stderr)
        return False # Indicate recovery might not position parser correctly

    def _read_block(self):
        """Read a block of settings for a list-based config section (e.g., firewall policy)."""
        items = []
        block_start_line = self.i # For debug
        # We assume the 'config <section>' line was already consumed by the caller
        # self.i += 1 - NO LONGER NEEDED HERE
        current_item = None
        nesting_level = 1
        if self.debug: print(f" >> Enter _read_block @ L{block_start_line+1}, Level {nesting_level}") # DEBUG

        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            if self.debug: print(f"    [L{self.i+1}, Lvl {nesting_level}] Read: {line}") # DEBUG
            current_item_id = current_item.get('id', current_item.get('name', 'None')) if current_item else 'None'

            # Handle nested config blocks first
            if line.startswith('config '):
                 nesting_level += 1
                 # Extract nested section name (handle potential quotes)
                 match_nested_section = self.SECTION_RE.match(line)
                 if match_nested_section:
                     nested_section_name = match_nested_section.group(1).strip().replace('"', '') # Remove quotes if present
                 else:
                     # Fallback or log warning if SECTION_RE fails (shouldn't happen often)
                     print(f"Warning [Line {self.i+1}]: Could not properly extract nested section name from: {line}", file=sys.stderr)
                     nested_section_name = line.split(None, 1)[1].strip()

                 nested_key = nested_section_name.lower().replace(' ','_').replace('-','_')

                 # Determine if nested block is list or settings
                 peek_i = self.i + 1
                 is_list_block = False
                 while peek_i < len(self.lines):
                     peek_line = self.lines[peek_i].strip()
                     if not peek_line or peek_line.startswith('#'):
                         peek_i += 1
                         continue
                     if self.EDIT_RE.match(peek_line):
                         is_list_block = True
                     break # Found first significant line

                 # Recursively read the nested block
                 if is_list_block:
                     nested_data = self._read_block()
                 else:
                     nested_data = self._read_settings()

                 nesting_level -= 1 # Decrement after the recursive call returns

                 if current_item is not None:
                     # Store nested data under the normalized key
                     # Handle potential conflicts if key exists? Overwrite for now.
                     current_item[nested_key] = nested_data
                 else:
                     # This case (nested config outside an 'edit' item) might be unusual
                     # Store it at the list level? Needs investigation based on FortiOS structure.
                     print(f"Warning [Line {self.i+1}]: Nested config block '{nested_section_name}' found outside an 'edit' item. Storing may be ambiguous.", file=sys.stderr)
                     # Perhaps store with a special key in the last item? Or create a dummy item?
                     # Safest for now is to potentially lose it if not inside an item.

                 # Check if recursive call consumed the 'end' line appropriately
                 # The recursive call should place self.i *after* the 'end' it consumed.
                 # No need to increment self.i here, the recursive call did it.
                 continue # Continue to the next line after the nested block

            # --- Match Standard Commands ---
            m_edit = self.EDIT_RE.match(line)
            m_set = self.SET_RE.match(line)
            m_append = self.APPEND_RE.match(line) # ADDED APPEND
            m_unset = self.UNSET_RE.match(line)   # ADDED UNSET
            m_next = self.NEXT_RE.match(line)
            m_end = self.END_RE.match(line)

            if m_edit:
                if current_item is not None:
                    items.append(current_item) # Save previous item
                edit_val = m_edit.group(1) or m_edit.group(2) # Quoted or unquoted name
                # Determine if the edit value is likely an integer ID or a string name
                id_key = 'id' if edit_val.isdigit() else 'name'
                current_item = {id_key: edit_val}
            elif m_set and current_item is not None:
                key = m_set.group(1).replace('-', '_') # Normalize key
                raw_val = m_set.group(2).strip()     # Get the raw value part

                # --- Robust Value Parsing ---
                # 1. Handle explicitly quoted single values
                if raw_val.startswith('"') and raw_val.endswith('"'):
                    val = raw_val[1:-1]
                # 2. Handle multi-word values, potentially with quotes inside
                elif ' ' in raw_val:
                    # Try splitting respecting quotes
                    split_vals = []
                    current_val = ''
                    in_quotes = False
                    for char in raw_val:
                        if char == '"':
                            in_quotes = not in_quotes
                        elif char == ' ' and not in_quotes:
                            if current_val: # Append if non-empty
                                split_vals.append(current_val)
                            current_val = ''
                        else:
                            current_val += char
                    if current_val: # Append the last part
                        split_vals.append(current_val)

                    # Special case: 'set ip <ip> <mask>' or 'set subnet <ip> <mask>'
                    if key in ['ip', 'subnet'] and len(split_vals) == 2:
                        ip_part = split_vals[0]
                        mask_part = split_vals[1]
                        try:
                            prefix = self._mask_to_prefix(mask_part)
                            if prefix is not None:
                                # Validate the IP part as well
                                ipaddress.ip_address(ip_part)
                                val = f"{ip_part}/{prefix}" # Store as ip/prefix string
                            else:
                                val = f"{ip_part}/{mask_part}" # Store as ip/mask if conversion failed
                                # Warning printed in _mask_to_prefix
                        except ValueError:
                            print(f"Warning [Line {self.i+1}]: Invalid IP/mask format '{ip_part} {mask_part}' for key '{key}'. Storing as is.", file=sys.stderr)
                            val = f"{ip_part}/{mask_part}" # Store the potentially problematic value
                    # If multiple values remain after splitting, store as list
                    elif len(split_vals) > 1:
                         # Check if it looks like multiple simple values (e.g., set member a b c)
                         # or a single value that happened to contain spaces but wasn't fully quoted
                         # Heuristic: If no internal quotes were detected, treat as list.
                         # If internal quotes were involved, maybe treat as single string? Needs refinement.
                         # For now, assume space separation means list if not fully quoted start/end.
                        val = split_vals
                    # Otherwise, treat as single value (might have spaces if improperly quoted)
                    else:
                        val = raw_val # Store the raw value if splitting logic didn't produce multiple items
                # 3. Handle simple single values
                else:
                    val = raw_val

                # Store the processed value
                current_item[key] = val
                if self.debug: print(f"       -> Stored set: {key} = {val}") # DEBUG

            # --- Handle append/unset (Store differently for potential diffing?) ---
            elif m_append and current_item is not None:
                 key = m_append.group(1).replace('-', '_')
                 raw_val = m_append.group(2).strip()
                 # Parse value similar to 'set'
                 if raw_val.startswith('"') and raw_val.endswith('"'):
                     append_val = raw_val[1:-1]
                 else:
                     # Simplified: treat appended value as single string for now
                     # TODO: Enhance parsing if lists can be appended piece by piece
                     append_val = raw_val

                 # Store append operations - maybe in a separate structure or flag?
                 # Simple approach: Ensure key exists as a list and append
                 if key not in current_item:
                     current_item[key] = []
                 elif not isinstance(current_item[key], list):
                     # Promote existing single value to list
                     current_item[key] = [current_item[key]]
                 current_item[key].append(append_val)
                 if self.debug: print(f"       -> Handled append for key '{key}', value '{append_val}'") # DEBUG

            elif m_unset and current_item is not None:
                 key = m_unset.group(1).replace('-', '_')
                 # Mark the key as unset? Or remove it? Removing is simpler for final state.
                 if key in current_item:
                     del current_item[key]
                 # TODO: Store unset operations if needed for diffing
                 if self.debug: print(f"       -> Handled unset for key '{key}'") # DEBUG

            elif m_next:
                 if current_item is not None:
                     items.append(current_item)
                 current_item = None # Reset for the next item
            elif m_end:
                 nesting_level -= 1
                 if nesting_level == 0:
                     if current_item is not None:
                         items.append(current_item) # Append the last item
                     self.i += 1 # Consume 'end'
                     if self.debug: print(f" << Exit _read_block (found end) @ L{self.i}, Final Level {nesting_level}") # DEBUG
                     return items # Return list of parsed items
                 else:
                     # This 'end' closes a nested block handled earlier. Just continue.
                     pass
            elif not line or line.startswith('#'):
                 pass # Skip comments and empty lines
            # --- ADDED: Handle unexpected lines ---
            else:
                 print(f"Warning [Line {self.i+1}]: Skipping unexpected line inside block for item '{current_item_id}': {line}", file=sys.stderr)

            self.i += 1 # Move to the next line

        # End of loop (likely reached EOF)
        print(f"Warning: Reached end of file while reading block (nesting level {nesting_level}).", file=sys.stderr)
        if current_item is not None:
            items.append(current_item) # Append the last item if loop terminated abruptly
        if self.debug: print(f" << Exit _read_block (EOF) @ L{self.i}, Final Level {nesting_level}") # DEBUG
        return items

    def _read_settings(self):
        """Read a block of settings for a single-item config section (e.g., system dns)."""
        settings = {}
        block_start_line = self.i # For debug
        # We assume the 'config <section>' line was already consumed by the caller
        # self.i += 1 - NO LONGER NEEDED HERE
        nesting_level = 1
        if self.debug: print(f" >> Enter _read_settings @ L{block_start_line+1}, Level {nesting_level}") # DEBUG

        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            if self.debug: print(f"    [L{self.i+1}, Lvl {nesting_level}] Read: {line}") # DEBUG

            # Handle nested config blocks first
            if line.startswith('config '):
                 nesting_level += 1
                 # Extract nested section name (handle potential quotes)
                 match_nested_section = self.SECTION_RE.match(line)
                 if match_nested_section:
                     nested_section_name = match_nested_section.group(1).strip().replace('"', '')
                 else:
                     print(f"Warning [Line {self.i+1}]: Could not properly extract nested section name from: {line}", file=sys.stderr)
                     nested_section_name = line.split(None, 1)[1].strip()

                 nested_key = nested_section_name.lower().replace(' ','_').replace('-','_')

                 # Determine if nested block is list or settings
                 peek_i = self.i + 1
                 is_list_block = False
                 while peek_i < len(self.lines):
                     peek_line = self.lines[peek_i].strip()
                     if not peek_line or peek_line.startswith('#'):
                         peek_i += 1
                         continue
                     if self.EDIT_RE.match(peek_line):
                         is_list_block = True
                     break

                 # Recursively read the nested block
                 if is_list_block:
                      nested_data = self._read_block()
                 else:
                      nested_data = self._read_settings()

                 nesting_level -= 1 # Decrement after the recursive call returns

                 # Store nested data under the normalized key
                 settings[nested_key] = nested_data

                 # Continue to the next line after the nested block
                 continue

            # --- Match Standard Commands ---
            m_set = self.SET_RE.match(line)
            m_append = self.APPEND_RE.match(line) # ADDED APPEND
            m_unset = self.UNSET_RE.match(line)   # ADDED UNSET
            m_end = self.END_RE.match(line)

            if m_set:
                key = m_set.group(1).replace('-', '_') # Normalize key
                raw_val = m_set.group(2).strip()     # Get the raw value part

                # --- Robust Value Parsing (same logic as _read_block) ---
                if raw_val.startswith('"') and raw_val.endswith('"'):
                    val = raw_val[1:-1]
                elif ' ' in raw_val:
                    split_vals = []
                    current_val = ''
                    in_quotes = False
                    for char in raw_val:
                        if char == '"':
                            in_quotes = not in_quotes
                        elif char == ' ' and not in_quotes:
                            if current_val:
                                split_vals.append(current_val)
                            current_val = ''
                        else:
                            current_val += char
                    if current_val:
                        split_vals.append(current_val)

                    if key in ['ip', 'subnet'] and len(split_vals) == 2:
                        ip_part = split_vals[0]
                        mask_part = split_vals[1]
                        try:
                            prefix = self._mask_to_prefix(mask_part)
                            if prefix is not None:
                                ipaddress.ip_address(ip_part)
                                val = f"{ip_part}/{prefix}"
                            else:
                                val = f"{ip_part}/{mask_part}"
                        except ValueError:
                            print(f"Warning [Line {self.i+1}]: Invalid IP/mask format '{ip_part} {mask_part}' for key '{key}'. Storing as is.", file=sys.stderr)
                            val = f"{ip_part}/{mask_part}"
                    elif len(split_vals) > 1:
                        val = split_vals
                    else:
                        val = raw_val
                else:
                    val = raw_val

                settings[key] = val
                if self.debug: print(f"       -> Stored set: {key} = {val}") # DEBUG

            elif m_append:
                 key = m_append.group(1).replace('-', '_')
                 raw_val = m_append.group(2).strip()
                 if raw_val.startswith('"') and raw_val.endswith('"'):
                     append_val = raw_val[1:-1]
                 else:
                     append_val = raw_val

                 if key not in settings:
                     settings[key] = []
                 elif not isinstance(settings[key], list):
                     settings[key] = [settings[key]]
                 settings[key].append(append_val)
                 if self.debug: print(f"       -> Handled append for key '{key}', value '{append_val}'") # DEBUG

            elif m_unset:
                 key = m_unset.group(1).replace('-', '_')
                 if key in settings:
                     del settings[key]
                 if self.debug: print(f"       -> Handled unset for key '{key}'") # DEBUG

            elif m_end:
                 nesting_level -= 1
                 if nesting_level == 0:
                     self.i += 1 # Consume 'end'
                     if self.debug: print(f" << Exit _read_settings (found end) @ L{self.i}, Final Level {nesting_level}") # DEBUG
                     return settings # Return the dictionary of settings
                 else:
                     # This 'end' closes a nested block.
                     pass
            elif not line or line.startswith('#'):
                 pass # Skip comments and empty lines
            # --- ADDED: Handle unexpected lines ---
            else:
                 print(f"Warning [Line {self.i+1}]: Skipping unexpected line inside settings block: {line}", file=sys.stderr)

            self.i += 1 # Move to the next line

        # End of loop (likely reached EOF)
        print(f"Warning: Reached end of file while reading settings (nesting level {nesting_level}).", file=sys.stderr)
        if self.debug: print(f" << Exit _read_settings (EOF) @ L{self.i}, Final Level {nesting_level}") # DEBUG
        return settings

    # --- Specific Section Handlers --- 
    # These methods parse specific 'config ...' sections.
    # They typically call _read_block() or _read_settings() and store the result
    # in the appropriate attribute of the self.model or VDOM sub-model.

    def _get_target_model(self):
         """Returns the correct model (main or VDOM) based on current_vdom."""
         if self.current_vdom and self.current_vdom != 'global' and self.current_vdom in self.model.vdoms:
             return self.model.vdoms[self.current_vdom]
         else:
             # Use main model for global, root, or if VDOM context is missing/invalid
             return self.model 
             
    def _handle_router_static(self):
        target_model = self._get_target_model()
        items = self._read_block()
        processed_routes = []
        for idx, item in enumerate(items):
             item['name'] = item.get('seq_num', f'static_route_{idx+1}')
             
             # --- FIX START: Convert dst list [ip, mask] to ip/prefix string ---
             dst_val = item.get('dst')
             if isinstance(dst_val, list) and len(dst_val) == 2:
                 ip_part = dst_val[0]
                 mask_part = dst_val[1]
                 prefix = self._mask_to_prefix(mask_part)
                 if prefix is not None:
                     item['dst'] = f"{ip_part}/{prefix}"
                 else:
                     # Fallback to ip/mask if prefix conversion failed
                     item['dst'] = f"{ip_part}/{mask_part}" 
                     print(f"Warning: Storing route destination '{item['name']}' as ip/mask due to mask parse failure.", file=sys.stderr)
             elif isinstance(dst_val, list): # Unexpected list format
                 print(f"Warning: Unexpected list format for destination in route '{item['name']}': {dst_val}. Storing as is.", file=sys.stderr)
                 # Keep original list if format is wrong
             # else: dst_val is already a string or None, leave it as is
             # --- FIX END ---
             
             processed_routes.append(item) # Add the potentially modified item
             
        target_model.routes.extend(processed_routes)

    def _handle_firewall_address(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                if item.get('type') == 'fqdn':
                     item['subnet'] = item.get('fqdn', item.get('name'))
                elif item.get('type') == 'wildcard':
                     item['subnet'] = item.get('wildcard', '?/?')
                     
                target_model.addresses[name] = item
            else:
                 print(f"Warning: Firewall address item found without name at line ~{self.i}. Skipping.", file=sys.stderr)
                 
    def _handle_firewall_addrgrp(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            members = item.get('member', [])
            if name:
                target_model.addr_groups[name] = members if isinstance(members, list) else [members]

    def _handle_firewall_service_custom(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                protocol = item.get('protocol', 'TCP/UDP/SCTP')
                port_key = None
                if protocol == 'TCP/UDP/SCTP':
                     port_key = 'tcp_portrange'
                     if 'udp_portrange' in item: port_key = 'udp_portrange'
                elif protocol == 'ICMP' or protocol == 'ICMP6':
                     item['port'] = f"type:{item.get('icmptype', 'any')}/code:{item.get('icmpcode', 'any')}"
                     item['protocol'] = protocol.upper()
                elif protocol == 'IP':
                     item['port'] = 'any'
                     item['protocol'] = 'IP'
                else:
                     port_key = f"{protocol.lower()}_portrange"
                
                if port_key and port_key in item:
                    port_val = item.get(port_key)
                    item['port'] = ' '.join(port_val) if isinstance(port_val, list) else port_val
                elif protocol not in ['ICMP', 'ICMP6', 'IP']:
                     item['port'] = item.get('port', 'any')
                
                if protocol == 'TCP/UDP/SCTP': item['protocol'] = 'TCP/UDP/SCTP'
                elif protocol: item['protocol'] = protocol.upper()
                     
                target_model.services[name] = item

    def _handle_firewall_service_group(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            members = item.get('member', [])
            if name:
                target_model.svc_groups[name] = members if isinstance(members, list) else [members]

    def _handle_firewall_policy(self):
        target_model = self._get_target_model()
        items = self._read_block()
        multi_value_keys = ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service']
        for item in items:
            item['id'] = item.get('policyid', item.get('id'))
            if not item.get('id'): 
                print(f"Warning: Policy found without ID near line {self.i}. Skipping.", file=sys.stderr)
                continue
                
            for key in multi_value_keys:
                 if key in item and not isinstance(item[key], list):
                     item[key] = [item[key]]
            item['comments'] = item.get('comments', '')
            target_model.policies.append(item)
            
    _handle_firewall_policy6 = _handle_firewall_policy 

    def _handle_system_interface(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                 secondary_ips = item.get('secondaryip', [])
                 if secondary_ips and not isinstance(secondary_ips, list):
                      print(f"Warning: Unexpected format for secondaryip in interface '{name}'. Expected list.", file=sys.stderr)
                      item['secondary_ip'] = []
                 elif secondary_ips:
                      item['secondary_ip'] = secondary_ips
                 else:
                      item['secondary_ip'] = []
                 
                 # --- START ADDITION: Capture description --- 
                 item['description'] = item.get('description', '') # Store description, default to empty string
                 # --- END ADDITION ---
                      
                 target_model.interfaces[name] = item

    def _handle_system_vlan(self): 
        target_model = self._get_target_model()
        items = self._read_block()
        print("Warning: Parsing 'config system vlan'. Structure might need adjustment.")
        for item in items:
             name = item.get('name')
             if name:
                 item['type'] = item.get('type', 'vlan')
                 target_model.interfaces[name] = item 

    def _handle_switch_controller_managed_switch(self):
        print("Warning: Skipping complex section 'switch-controller managed-switch'. Parsing not fully implemented.")
        self._skip_block()

    def _handle_switch_controller_vlan(self): 
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                 members = item.get('member', [])
                 item['members'] = [m.get('interface_name','?') for m in members] if isinstance(members, list) else []
                 target_model.vlans[name] = item

    def _handle_system_zone(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            interfaces = item.get('interface', [])
            if name:
                item['interface'] = interfaces if isinstance(interfaces, list) else [interfaces]
                target_model.zones[name] = item

    def _handle_firewall_vip(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                mapped_ips = item.get('mappedip', [])
                if mapped_ips and not isinstance(mapped_ips, list):
                     print(f"Warning: Unexpected format for mappedip in VIP '{name}'. Expected list.", file=sys.stderr)
                     item['mappedip'] = []
                elif not mapped_ips:
                     item['mappedip'] = []
                target_model.vips[name] = item
                
    _handle_firewall_vip6 = _handle_firewall_vip 

    def _handle_firewall_vipgrp(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            members = item.get('member', [])
            if name:
                target_model.vip_groups[name] = members if isinstance(members, list) else [members]
                
    _handle_firewall_vipgrp6 = _handle_firewall_vipgrp 

    def _handle_firewall_ippool(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                target_model.ippools[name] = item
                
    _handle_firewall_ippool6 = _handle_firewall_ippool 

    def _handle_system_dhcp_server(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
             ip_range_list = item.get('ip_range', [])
             if ip_range_list and isinstance(ip_range_list, list):
                 ip_range_data = ip_range_list[0] 
                 item['ip_range_str'] = f"{ip_range_data.get('start_ip','?')} - {ip_range_data.get('end_ip','?')}"
             else:
                 item['ip_range_str'] = "Not Configured"
                 
             # Handle nested 'config reserved_address' block
             reserved_list = item.get('reserved_address', [])
             item['reserved_addresses'] = reserved_list # Store the list of reserved dicts
                 
             target_model.dhcp_servers.append(item)

    def _handle_router_ospf(self):
        target_model = self._get_target_model()
        # This is a settings block, not a list block
        settings = self._read_settings()
        target_model.ospf = settings
        
    # OSPF sub-sections are handled when _read_settings encounters them recursively
    # Example nested handlers (called implicitly by recursion in _read_settings)
    # def _handle_router_ospf_area(self):
    #     # Called when 'config area' is found inside 'config router ospf'
    #     # Returns list of area dictionaries
    #     return self._read_block() 
    # def _handle_router_ospf_network(self):
    #     # Called for 'config network' inside ospf
    #     return self._read_block()
    # def _handle_router_ospf_interface(self):
    #      # Called for 'config ospf-interface' inside ospf
    #      return self._read_block()

    def _handle_router_bgp(self):
        target_model = self._get_target_model()
        settings = self._read_settings() # Reads the whole block including nested
        
        # Extract neighbors if present
        if 'neighbor' in settings and isinstance(settings['neighbor'], list):
            target_model.bgp_neighbors = settings.pop('neighbor') 
        else:
            target_model.bgp_neighbors = [] # Ensure it's an empty list if not found
            
        # Extract networks if present
        if 'network' in settings and isinstance(settings['network'], list):
            target_model.bgp_networks = settings.pop('network')
        else:
            target_model.bgp_networks = []
            
        # Store the remaining top-level BGP settings
        target_model.bgp = settings

    # BGP sub-sections handled implicitly by _read_settings recursion
    # def _handle_router_bgp_neighbor(self):

    def _handle_vpn_ipsec_phase1_interface(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                target_model.phase1[name] = item
                
    _handle_vpn_ipsec_phase1 = _handle_vpn_ipsec_phase1_interface # Alias

    def _handle_vpn_ipsec_phase2_interface(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                # Resolve src/dst selectors if they refer to address objects
                # This might be better done in a post-processing step or diagram generator
                target_model.phase2[name] = item
                
    _handle_vpn_ipsec_phase2 = _handle_vpn_ipsec_phase2_interface # Alias

    def _handle_firewall_shaper_traffic_shaper(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                target_model.traffic_shapers[name] = item

    def _handle_firewall_shaper_per_ip_shaper(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                target_model.shaper_per_ip[name] = item

    def _handle_firewall_dos_policy(self):
        target_model = self._get_target_model()
        items = self._read_block()
        # Uses ID
        for item in items:
            item['id'] = item.get('policyid', item.get('id'))
            multi_keys = ['srcaddr', 'dstaddr', 'service']
            for key in multi_keys:
                 if key in item and not isinstance(item[key], list):
                     item[key] = [item[key]]
            target_model.dos_policies.append(item)
            
    _handle_firewall_dos_policy6 = _handle_firewall_dos_policy # Alias

    def _handle_system_snmp_sysinfo(self):
        target_model = self._get_target_model()
        target_model.snmp_sysinfo = self._read_settings()

    def _handle_system_snmp_community(self):
        target_model = self._get_target_model()
        items = self._read_block()
        # Uses ID
        for item in items:
            comm_id = item.get('id')
            if comm_id:
                 # Handle nested host/host6 blocks
                 hosts = item.get('hosts', [])
                 item['hosts_parsed'] = [h.get('ip') for h in hosts if h.get('ip')] if isinstance(hosts, list) else []
                 hosts6 = item.get('hosts6', [])
                 item['hosts6_parsed'] = [h.get('ipv6') for h in hosts6 if h.get('ipv6')] if isinstance(hosts6, list) else []
                 target_model.snmp_communities[comm_id] = item

    def _handle_user_ldap(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                target_model.ldap_servers[name] = item

    def _handle_system_admin(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                 # Handle trusted hosts
                 hosts = []
                 for i in range(1, 11): # Max 10 trusted hosts
                     ip_key = f'trusthost{i}'
                     if ip_key in item and item[ip_key] != '0.0.0.0 0.0.0.0':
                         if isinstance(item[ip_key], list):
                             hosts.append(' '.join(item[ip_key]))
                         else:
                             hosts.append(item[ip_key])
                 item['trusted_hosts'] = hosts
                 target_model.admins[name] = item

    def _handle_system_ha(self):
        target_model = self._get_target_model()
        target_model.ha = self._read_settings()

    def _handle_system_ntp(self):
        target_model = self._get_target_model()
        target_model.ntp = self._read_settings()

    def _handle_system_dns(self):
        target_model = self._get_target_model()
        print(f"DEBUG: ENTER _handle_system_dns @ line {self.i+1}, VDOM: {self.current_vdom}") # DEBUG
        start_i = self.i
        settings = self._read_settings()
        print(f"DEBUG: EXIT _read_settings in dns handler. Start i: {start_i+1}, End i: {self.i+1}, Settings found: {bool(settings)}") # DEBUG
        target_model.dns = settings

    def _handle_vpn_ssl_settings(self):
        # Typically global, but check target model just in case
        target_model = self._get_target_model()
        target_model.ssl_settings = self._read_settings()

    def _handle_vpn_ssl_web_portal(self):
        target_model = self._get_target_model()
        items = self._read_block()
        for item in items:
            name = item.get('name')
            if name:
                # Handle bookmarks etc. if needed
                target_model.ssl_portals[name] = item

    def _handle_vpn_ssl_web_policy(self):
        target_model = self._get_target_model()
        items = self._read_block()
        # Uses ID usually? Check config. Assume 'id' or 'name'.
        for item in items:
             item['id'] = item.get('name', item.get('id')) # Prefer name if exists
             target_model.ssl_policies.append(item)
             
    def _handle_router_vrrp(self):
        target_model = self._get_target_model()
        items = self._read_block() # List block 'edit <vrid>'
        for item in items:
             vrid = item.get('id') # Keyed by VRID
             if vrid:
                 target_model.vrrp[vrid] = item
                 
    # --- Handler for Policy Routes ---
    def _handle_router_policy(self):
        target_model = self._get_target_model()
        items = self._read_block() 
        # Basic storage, can be refined later if specific fields need processing
        for item in items:
             item['id'] = item.get('seq_num', item.get('id')) # Use seq-num if available
             target_model.policy_routes.append(item)
                 
    # --- Settings Handlers --- 
    # These handle simple settings blocks, often global.
    
    def _handle_system_global(self):
        target_model = self._get_target_model() # Usually main model
        target_model.system_global = self._read_settings()
        
    # --- Security Profile Handlers --- 
    # These follow a common pattern: read block, store in dict by name.
    def _handle_profile_block(self, model_key):
         target_model = self._get_target_model()
         items = self._read_block()
         profile_dict = getattr(target_model, model_key, {}) # Get or init dict
         for item in items:
             name = item.get('name')
             if name:
                 profile_dict[name] = item
         setattr(target_model, model_key, profile_dict) # Update model
         
    def _handle_antivirus_profile(self): self._handle_profile_block('antivirus')
    def _handle_ips_sensor(self): self._handle_profile_block('ips')
    def _handle_webfilter_profile(self): self._handle_profile_block('web_filter')
    def _handle_application_list(self): self._handle_profile_block('app_control')
    def _handle_dlp_sensor(self): self._handle_profile_block('dlp')
    def _handle_emailfilter_profile(self): self._handle_profile_block('email_filter')
    def _handle_voip_profile(self): self._handle_profile_block('voip')
    def _handle_waf_profile(self): self._handle_profile_block('waf')
    def _handle_ssh_filter_profile(self): self._handle_profile_block('ssl_inspection') # Map to ssl? Check
    def _handle_ssl_ssh_profile(self): self._handle_profile_block('ssl_inspection')
    def _handle_icap_profile(self): self._handle_profile_block('icap')
    def _handle_gtp_profile(self): self._handle_profile_block('gtp')
    def _handle_dnsfilter_profile(self): self._handle_profile_block('system_dns_filter') # Map
    def _handle_wanopt_profile(self): self._handle_profile_block('wan_opt')
    
    # --- User/Authentication Handlers ---
    def _handle_user_radius(self): self._handle_profile_block('radius_servers')
    def _handle_user_group(self): self._handle_profile_block('user_groups')
    def _handle_user_fortitoken(self): 
         # Uses serial number as edit key
         target_model = self._get_target_model()
         items = self._read_block()
         token_dict = getattr(target_model, 'fortitoken', {})
         for item in items:
             serial = item.get('name') # Assuming edit key stored as 'name'
             if serial:
                 token_dict[serial] = item
         setattr(target_model, 'fortitoken', token_dict)
    def _handle_user_saml(self): self._handle_profile_block('saml')
    def _handle_user_fsso(self): self._handle_profile_block('fsso')

    # --- Schedule Handlers --- 
    def _handle_firewall_schedule_group(self): self._handle_profile_block('schedule_groups')
    def _handle_firewall_schedule_onetime(self): self._handle_profile_block('schedule_onetime')
    def _handle_firewall_schedule_recurring(self): self._handle_profile_block('schedule_recurring')
    
    # --- Other Feature Handlers --- 
    def _handle_firewall_sniffer(self): self._handle_profile_block('sniffer_profile') # Uses ID? Check.
    def _handle_system_fortiguard(self): self._get_target_model().fortiguard = self._read_settings()
    def _handle_log_syslogd_setting(self): # Example specific log handler
         target_model = self._get_target_model()
         settings = self._read_settings()
         log_settings = getattr(target_model, 'log_settings', {})
         log_settings['syslogd'] = settings # Store under a sub-key
         setattr(target_model, 'log_settings', log_settings)
         
    def _handle_system_sdwan(self): # Top level SDWAN settings
         target_model = self._get_target_model()
         settings = self._read_settings()
         # Merge settings into the main sd_wan dict
         sdwan_config = getattr(target_model, 'sd_wan', {})
         sdwan_config.update(settings)
         setattr(target_model, 'sd_wan', sdwan_config)
         
    # SD-WAN sub-configs (members, service, health-check) are handled by recursion in _read_settings
    # when parsing _handle_system_sdwan. They will appear as nested dicts/lists within target_model.sd_wan.

    def _handle_firewall_ldb_monitor(self): self._handle_profile_block('load_balance') # Store LB monitors
    def _handle_wireless_controller_setting(self): self._get_target_model().wireless_controller = self._read_settings()
    def _handle_switch_controller_global(self): self._get_target_model().switch_controller = self._read_settings()
    def _handle_system_fortisandbox(self): self._get_target_model().sandbox = self._read_settings()
    
    # --- Certificate Handlers --- 
    def _handle_vpn_certificate_local(self): self._handle_cert('local')
    def _handle_vpn_certificate_ca(self): self._handle_cert('ca')
    def _handle_vpn_certificate_remote(self): self._handle_cert('remote')
    def _handle_vpn_certificate_crl(self): self._handle_cert('crl')

    def _handle_cert(self, cert_type):
         target_model = self._get_target_model()
         items = self._read_block()
         cert_dict = getattr(target_model, 'certificate', {})
         if cert_type not in cert_dict: cert_dict[cert_type] = {}
         for item in items:
             name = item.get('name')
             if name:
                 cert_dict[cert_type][name] = item
         setattr(target_model, 'certificate', cert_dict)
         
    # --- Automation/Fabric/Management Handlers ---
    def _handle_system_automation_action(self): self._handle_profile_block('automation') # Store actions by name
    def _handle_system_sdn_connector(self): self._handle_profile_block('sdn_connector')
    def _handle_system_extender_controller_extender(self): self._handle_profile_block('extender')
    def _handle_system_csf(self): self._get_target_model().system_csf = self._read_settings()
    def _handle_system_central_management(self): self._get_target_model().system_central_mgmt = self._read_settings()
    def _handle_system_fm(self): self._get_target_model().system_fm = self._read_settings()
    def _handle_log_fortianalyzer_setting(self): self._get_target_model().system_fortianalyzer = self._read_settings()
    _handle_system_fortianalyzer = _handle_log_fortianalyzer_setting # Alias
    def _handle_log_fortisandbox_setting(self): self._get_target_model().system_fortisandbox = self._read_settings()
    _handle_system_fortisandbox = _handle_log_fortisandbox_setting # Alias

    # --- Legacy/Other VPN Handlers ---
    def _handle_vpn_l2tp(self): self._get_target_model().vpn_l2tp = self._read_settings()
    def _handle_vpn_pptp(self): self._get_target_model().vpn_pptp = self._read_settings()
    def _handle_vpn_ssl_client(self): 
         print("Warning: Parsing 'config vpn ssl client'. This section is unusual, verify structure.", file=sys.stderr)
         # Assume settings block for now
         self._get_target_model().vpn_ssl_client = self._read_settings()
         
    # --- System Settings Handlers ---
    def _handle_system_replacemsg_group(self): self._handle_profile_block('system_replacemsg')
    def _handle_system_accprofile(self): self._handle_profile_block('system_accprofile')
    def _handle_system_api_user(self): self._handle_profile_block('system_api_user')
    def _handle_system_sso_admin(self): self._handle_profile_block('system_sso_admin')
    def _handle_system_password_policy(self): self._get_target_model().system_password_policy = self._read_settings()
    def _handle_firewall_interface_policy(self): self._handle_profile_block('system_interface_policy') # Treat as profile block? Needs ID?
    def _handle_system_auto_update(self): self._get_target_model().system_auto_update = self._read_settings()
    def _handle_system_session_ttl(self): self._get_target_model().system_session_ttl = self._read_settings()
    # session-ttl sub-config 'port' handled by recursion
    def _handle_system_gre_tunnel(self): self._handle_profile_block('system_gre_tunnel')
    def _handle_system_ddns(self): self._handle_profile_block('system_ddns') # Uses ID
    def _handle_system_dns_database(self): self._handle_profile_block('system_dns_database')
    # dns-database sub-config 'dns-entry' handled by recursion
    def _handle_system_dns_server(self): self._handle_profile_block('system_dns_server')
    def _handle_system_proxy_arp(self): self._handle_profile_block('system_proxy_arp') # Uses ID
    def _handle_system_virtual_wire_pair(self): self._handle_profile_block('system_virtual_wire_pair')
    def _handle_system_wccp(self): self._handle_profile_block('system_wccp') # Uses ID (service-id)
    def _handle_system_sit_tunnel(self): self._handle_profile_block('system_sit_tunnel')
    def _handle_system_ipip_tunnel(self): self._handle_profile_block('system_ipip_tunnel')
    def _handle_system_vxlan(self): self._handle_profile_block('system_vxlan')
    # vxlan sub-config 'remote-ip' handled by recursion
    def _handle_system_geneve(self): self._handle_profile_block('system_geneve')
    def _handle_system_network_visibility(self): self._get_target_model().system_network_visibility = self._read_settings()
    def _handle_system_ptp(self): self._get_target_model().system_ptp = self._read_settings()
    def _handle_system_tos_based_priority(self): self._handle_profile_block('system_tos_based_priority') # Uses ID
    def _handle_system_email_server(self): self._get_target_model().system_email_server = self._read_settings()
    def _handle_ips_urlfilter_dns(self): self._get_target_model().system_ips_urlfilter_dns = self._read_settings() # Settings? Check format.

    # --- Generic Handler --- 
    def _handle_generic_section(self, raw_section_name, normalized_section_name):
        """Handles unrecognized config sections by storing raw data."""
        target_model = self._get_target_model()
        # print(f"Info: Using generic handler for section: {raw_section_name}")
        # Decide if it's likely a list block or settings block by peeking ahead
        peek_i = self.i + 1
        is_list_block = False
        while peek_i < len(self.lines):
            peek_line = self.lines[peek_i].strip()
            if not peek_line or peek_line.startswith('#'):
                peek_i += 1
                continue
            if self.EDIT_RE.match(peek_line):
                is_list_block = True
            break
            
        data = None
        try:
            if is_list_block:
                # print(f"DEBUG: Generic handler reading '{raw_section_name}' as list block.")
                data = self._read_block()
            else:
                # print(f"DEBUG: Generic handler reading '{raw_section_name}' as settings block.")
                data = self._read_settings()
        except Exception as e:
            print(f"ERROR: Generic handler failed for section '{raw_section_name}' at line {self.i+1}: {e}", file=sys.stderr)
            # Attempt to recover by skipping
            # Reset self.i to the start of the block before skipping
            # Find the line number where the section started (tricky without storing it)
            # Simplification: assume self.i is roughly correct before skip attempt
            self._skip_block()
            data = f"Error parsing section: {e}" # Store error marker
            
        # Store the data in the model under a generic key
        generic_data = getattr(target_model, 'generic_configs', {})
        # Use normalized name, maybe prefix to avoid clashes?
        storage_key = f"generic_{normalized_section_name}"
        generic_data[storage_key] = {
             'raw_name': raw_section_name,
             'data': data
        }
        setattr(target_model, 'generic_configs', generic_data)
        # print(f"Stored generic data for {raw_section_name} under key {storage_key}")

# --- Main Execution --- 

def main():
    p = argparse.ArgumentParser(description="FortiGate Comprehensive Table Parser & Diagram Generator")
    p.add_argument('config_file', help="FortiGate CLI export text file")
    p.add_argument('--output', default='network_topology', help="Base name for output files (diagrams, reports)")
    # Path Tracing Arguments
    p.add_argument('--trace-src', help="Source IP address for path trace")
    p.add_argument('--trace-dst', help="Destination IP address for path trace")
    p.add_argument('--trace-port', help="Destination port/service for path trace (required if src/dst provided)")
    p.add_argument('--trace-proto', default='tcp', help="Protocol for path trace (tcp, udp, icmp - default: tcp)")
    # Output format arguments (optional)
    p.add_argument('--no-diagram', action='store_true', help="Skip diagram generation")
    p.add_argument('--no-tables', action='store_true', help="Skip printing ASCII tables to console")
    # ADDED Debug argument
    p.add_argument('--debug', action='store_true', help="Enable verbose debug output during parsing")

    args = p.parse_args()

    try:
        # Read the entire config file
        with open(args.config_file, 'r', encoding='utf-8') as f:
             config_lines = f.readlines()
    except OSError as e:
        print(f"Error opening config file '{args.config_file}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
         print(f"Error reading config file '{args.config_file}': {e}", file=sys.stderr)
         sys.exit(1)

    print(f"Parsing configuration file: {args.config_file}...")
    # Pass debug flag to parser
    parser = FortiParser(config_lines, debug=args.debug)
    try:
        model = parser.parse()
        # Removed redundant print("Parsing complete.") here, moved inside parse()
    except Exception as e:
        print(f"\n!!! Critical parsing error encountered: {e}", file=sys.stderr)
        print("Attempting to proceed, but results may be incomplete.", file=sys.stderr)

    # --- Initialize Generator --- 
    # Requires the parsed model
    generator = NetworkDiagramGenerator(model)

    # --- Conditional Execution: Trace or Tables/Diagram ---
    if args.trace_src and args.trace_dst:
        if not args.trace_port:
             print("Error: --trace-port is required when using --trace-src and --trace-dst.", file=sys.stderr)
             sys.exit(1)

        print(f"\n--- Performing Network Path Trace ---")
        print(f"Source:      {args.trace_src}")
        print(f"Destination: {args.trace_dst}")
        print(f"Port:        {args.trace_port}")
        print(f"Protocol:    {args.trace_proto}")
        print("-" * 35)

        # Run the trace using the generator's method
        try:
            path_result, status_msg = generator.trace_network_path(
                source_ip=args.trace_src,
                dest_ip=args.trace_dst,
                dest_port=args.trace_port,
                protocol=args.trace_proto
            )
        except Exception as e:
             print(f"\n!!! Error during path trace execution: {e}", file=sys.stderr)
             print("Please check the trace parameters and the parsed configuration.", file=sys.stderr)
             sys.exit(1)

        # Print the trace results
        print(f"\n--- Trace Result ---")
        print(f"Status: {status_msg}")
        if path_result:
            print("\nPath Details (Simulated Hops):")
            for hop_info in path_result:
                 print(f"  Hop {hop_info.get('hop')}: [{hop_info.get('type')}]")
                 # Print relevant details based on type
                 details_to_print = []
                 if 'detail' in hop_info: details_to_print.append(f"    Detail: {hop_info['detail']}")
                 if 'interface' in hop_info: details_to_print.append(f"    Interface: {hop_info['interface']}")
                 if 'policy_id' in hop_info and hop_info['policy_id']: details_to_print.append(f"    Policy ID: {hop_info['policy_id']}")
                 if 'egress_interface' in hop_info: details_to_print.append(f"    Egress IF: {hop_info['egress_interface']}")
                 if 'post_nat_src' in hop_info and hop_info['pre_nat_src'] != hop_info['post_nat_src']: details_to_print.append(f"    NAT Src: {hop_info['pre_nat_src']} -> {hop_info['post_nat_src']}")
                 if 'post_nat_dst' in hop_info and hop_info['pre_nat_dst'] != hop_info['post_nat_dst']: details_to_print.append(f"    NAT Dst: {hop_info['pre_nat_dst']} -> {hop_info['post_nat_dst']}")
                 if 'post_nat_port' in hop_info and hop_info['pre_nat_port'] != hop_info['post_nat_port']: details_to_print.append(f"    NAT Port: {hop_info['pre_nat_port']} -> {hop_info['post_nat_port']}")
                 print("\n".join(details_to_print))
        print("-" * 20)

    else:
        # --- Default Behavior: Generate Diagram & Reports --- 
        print("\n--- Generating Reports and Diagram --- ")
        
        # Generate diagram (and reports) using the generator
        if not args.no_diagram:
             try:
                 # This method now handles analysis, rendering, unused report, and summary
                 generator.generate_diagram(args.output)
             except ImportError as e:
                  print(f"\nError: Failed to import required library for diagrams: {e}", file=sys.stderr)
                  print("Please ensure 'graphviz' Python library and the Graphviz binaries are installed.", file=sys.stderr)
             except Exception as e:
                  print(f"\n!!! Error during diagram/report generation: {e}", file=sys.stderr)
        else:
             print("Skipping diagram generation as requested.")
             # Need to run analysis manually if diagram is skipped but we want reports/tree
             try:
                 generator.analyze_relationships()
                 # Generate reports even if diagram skipped
                 # generator.generate_unused_report(args.output)
                 # summary = generator.generate_relationship_summary()
                 # print("\n" + summary)
             except Exception as e:
                 print(f"\n!!! Error during analysis for reports: {e}", file=sys.stderr)

        # --- Generate and Print Connectivity Tree --- 
        # Print this regardless of --no-tables, as it provides different info
        try:
            connectivity_tree_output = generator.generate_connectivity_tree()
            print("\n" + connectivity_tree_output)
        except Exception as e:
             print(f"\n!!! Error generating connectivity tree: {e}", file=sys.stderr)

        # --- Optional: Print ASCII Tables --- 
        if not args.no_tables:
            print("\n--- Generating Console Tables (Summary) --- ")
            # Static Routes
            rows = [[r.get('name','-'), r.get('dst','-'), r.get('gateway','-'), r.get('device','-'),
                     r.get('distance','-'), 'Yes' if r.get('status') != 'disable' else 'No', r.get('comment','-')]
                    for r in model.routes]
            print_table("Static Routes", ["Name","Destination","Gateway","Interface","Distance","Enabled","Comment"], rows)
            
            # Interfaces
            rows = [[n, i.get('ip','DHCP/Unset'), i.get('type','physical'), ','.join(i.get('allowaccess',[])),
                     i.get('role','undefined'), i.get('vdom','root'), i.get('alias','-'), 
                     i.get('status','unknown')]
                    for n,i in model.interfaces.items()]
            print_table("Interfaces", ["Name","IP/Mask","Type","Access","Role","VDOM","Alias","Status"], rows)

            # Zones
            rows = [[n, ','.join(z.get('interface',[])), z.get('intrazone','deny')]
                    for n,z in model.zones.items()]
            print_table("Zones", ["Name","Interfaces","Intrazone Action"], rows)
            
            # Policies (simplified table)
            rows = []
            for p in model.policies:
                nat_info = 'No NAT'
                if p.get('nat') == 'enable':
                     nat_info = f"NAT: Outgoing IF" if p.get('ippool') != 'enable' else f"NAT Pool: {p.get('poolname', '?')}"
                rows.append([
                     p.get('id','?'), ','.join(p.get('srcintf',[])), ','.join(p.get('dstintf',[])),
                     ','.join(p.get('srcaddr',[])), ','.join(p.get('dstaddr',[])),
                     ','.join(p.get('service',[])), p.get('action','deny'),
                     'Yes' if p.get('status') != 'disable' else 'No', nat_info,
                     p.get('logtraffic','off')
                 ])
            print_table("Firewall Policies (Summary)", ["ID","SrcIntf","DstIntf","SrcAddr","DstAddr","Service","Action","Enabled","NAT","Log"], rows)
            
            # Address Objects
            rows = [[n, a.get('type','?'), a.get('subnet','?'), a.get('comment','-')]
                    for n,a in model.addresses.items()]
            print_table("Address Objects", ["Name","Type","Subnet/FQDN/Range","Comment"], rows)

            # Address Groups
            rows = [[n, ','.join(m)] for n,m in model.addr_groups.items()]
            print_table("Address Groups", ["Name","Members"], rows)
            
            # Custom Services
            rows = []
            for n, s in model.services.items():
                 port_info = s.get('port', 'any')
                 # Handle potential list format for ports from older parsing logic if needed
                 if isinstance(port_info, list): port_info = ' '.join(port_info)
                 rows.append([n, s.get('protocol','?'), port_info, s.get('comment','-')])
            print_table("Custom Services", ["Name","Protocol","Port Range/Info","Comment"], rows)

            # Service Groups
            rows = [[n, ','.join(m)] for n,m in model.svc_groups.items()]
            print_table("Service Groups", ["Name","Members"], rows)

            # VIPs (Virtual IPs)
            rows = []
            for n, v in model.vips.items():
                 extip = v.get('extip','?')
                 mappedip_list = v.get('mappedip', [])
                 # Ensure mappedip is always treated as a list for consistency
                 if not isinstance(mappedip_list, list): mappedip_list = [mappedip_list] 
                 mappedip_str = ', '.join([m.get('range', '?') for m in mappedip_list]) if mappedip_list else '?'
                 
                 portfwd = 'No'
                 fwd_details = []
                 if v.get('portforward') == 'enable':
                     portfwd = 'Yes'
                     fwd_details.append(f"Proto: {v.get('protocol', '?')}")
                     fwd_details.append(f"Ext: {v.get('extport', '?')}")
                     fwd_details.append(f"Mapped: {v.get('mappedport', '?')}")
                     portfwd = f"Yes ({', '.join(fwd_details)})"

                 rows.append([n, extip, mappedip_str, v.get('extintf','any'), portfwd, v.get('comment','-')])
            print_table("VIPs (Virtual IPs)", ["Name","External IP","Mapped IP(s)","Interface","Port Fwd","Comment"], rows)

            # VIP Groups
            rows = [[n, ','.join(m)] for n,m in model.vip_groups.items()]
            print_table("VIP Groups", ["Name","Members"], rows)

            # IP Pools
            rows = [[n, p.get('type','overload'), f"{p.get('startip','?')} - {p.get('endip','?')}", p.get('comment','-')]
                    for n,p in model.ippools.items()]
            print_table("IP Pools", ["Name","Type","IP Range","Comment"], rows)

            # VPN Phase 1
            rows = []
            for n, p1 in model.phase1.items():
                rows.append([n, p1.get('interface','-'), p1.get('remote_gw','-'), 
                             p1.get('psksecret','*SECRET*'), p1.get('proposal','default'),
                             p1.get('mode','main'), p1.get('status','enable')])
            print_table("VPN Phase 1", ["Name","Interface","Remote GW","PSK","Proposal","Mode","Status"], rows)

            # VPN Phase 2
            rows = []
            for n, p2 in model.phase2.items():
                src_sel = f"{p2.get('src_subnet','0.0.0.0/0')} ({p2.get('src_addr_type','subnet')})" if p2.get('src_subnet') else p2.get('src_name', '-')
                dst_sel = f"{p2.get('dst_subnet','0.0.0.0/0')} ({p2.get('dst_addr_type','subnet')})" if p2.get('dst_subnet') else p2.get('dst_name', '-')
                rows.append([n, p2.get('phase1name','-'), src_sel, dst_sel, 
                             p2.get('proposal','default'), 'Yes' if p2.get('auto_negotiate')=='enable' else 'No',
                             p2.get('keylifeseconds','-')])
            print_table("VPN Phase 2", ["Name","Phase1 Name","Source Selector","Dest Selector","Proposal","Auto Neg.","Keylife (s)"], rows)
            
            # DHCP Servers
            rows = []
            for s in model.dhcp_servers:
                 rows.append([s.get('id','-'), s.get('interface','-'), s.get('ip_range_str','-'),
                              s.get('default_gateway','-'), s.get('netmask','-'), s.get('dns_service','default')])
            print_table("DHCP Servers", ["ID","Interface","IP Range","Gateway","Netmask","DNS"], rows)

            # System DNS
            rows = [[model.dns.get('primary','-'), model.dns.get('secondary','-'), model.dns.get('domain','-')]] if model.dns else []
            print_table("System DNS", ["Primary","Secondary","Domain"], rows)
            
            # System NTP
            ntp_enabled = model.ntp.get('ntpsync') == 'enable'
            server_mode = model.ntp.get('type','fortiguard')
            server_details = model.ntp.get('ntpserver','FortiGuard Servers') if server_mode == 'fortiguard' else model.ntp.get('server','?')
            rows = [['Yes' if ntp_enabled else 'No', server_mode, server_details]] if model.ntp else []
            print_table("System NTP", ["Enabled","Mode","Server(s)"], rows)
            
            # Administrators
            rows = []
            for n, a in model.admins.items():
                 # Format trusted hosts
                 trusted_hosts_raw = a.get('trusted_hosts', [])
                 trusted_hosts_formatted = []
                 if trusted_hosts_raw:
                     for host_entry in trusted_hosts_raw:
                         if isinstance(host_entry, list):
                             trusted_hosts_formatted.append(' '.join(host_entry)) # Rejoin IP and mask
                         elif isinstance(host_entry, str):
                             trusted_hosts_formatted.append(host_entry)
                         # else: ignore unexpected types in the list
                     trusted_display = ', '.join(trusted_hosts_formatted) 
                 else:
                     trusted_display = 'Any'
                 
                 # Format VDOMs
                 vdoms_raw = a.get('vdoms')
                 vdom_display = ','.join(vdoms_raw) if isinstance(vdoms_raw, list) else (vdoms_raw if vdoms_raw else '-') # Handle list or single string

                 rows.append([n, a.get('accprofile','-'), trusted_display, vdom_display])
            print_table("Administrators", ["Name","Access Profile","Trusted Hosts","VDOMs"], rows)

            # Security Profiles (List Names)
            rows = [[n, p.get('comment', '-'), 'Yes' if p.get('botnet_c_c_scan') == 'enable' else 'No'] for n, p in model.antivirus.items()]
            print_table("Antivirus Profiles", ["Name", "Comment", "Botnet C&C Scan"], rows)
            rows = [[n, p.get('comment', '-'), 'Enabled' if p.get('status') == 'enable' else 'Disabled'] for n, p in model.ips.items()]
            print_table("IPS Sensors", ["Name", "Comment", "Status"], rows)
            rows = [[n, p.get('comment', '-'), p.get('fortiguard_category', '?')] for n, p in model.web_filter.items()]
            print_table("Web Filter Profiles", ["Name", "Comment", "FortiGuard Category Action"], rows)
            rows = [[n, p.get('comment', '-'), 'Yes' if p.get('block_malicious_applications') == 'enable' else 'No'] for n, p in model.app_control.items()]
            print_table("Application Control Profiles", ["Name", "Comment", "Block Malicious Apps"], rows)

        else:
            print("Skipping console table generation.")
            
    print("\nProcessing finished.")

if __name__ == '__main__':
    main()
