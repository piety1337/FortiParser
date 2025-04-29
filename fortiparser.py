#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FortiGate Parser & Diagram Generator

Parses a FortiGate configuration file, generates diagrams, reports,
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
                # --- Advance parser index PAST the 'config vdom' line BEFORE calling handler ---
                self.i += 1 
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
                # For now, assume it's just a container like VDOMs, main loop handles inner blocks.
                # If 'set' commands are allowed here, we'd need a read_settings loop until 'end'.
                last_successful_line = self.i
                # if self.debug: print(f"[L{self.i}] Exiting Global config") # DEBUG # This message might be premature
                continue # Let main loop handle sections inside 'config global'

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

                # --- Advance parser index PAST the 'config ...' line BEFORE calling handler ---
                self.i += 1
                start_block_content_index = self.i # Mark where the block's content starts

                if handler:
                    try:
                        handler() # Call the specific handler
                        # Handler should call read_block/read_settings which advances self.i past the section's end
                        last_successful_line = self.i
                    except Exception as e:
                        print(f"ERROR: Handler {handler_method_name} failed processing section '{raw_section_name}' starting near line {original_line_index + 1}: {e}", file=sys.stderr)
                        print(f"Attempting to recover by skipping to next likely block start or end...", file=sys.stderr)
                        # --- Recovery Attempt --- #
                        # Reset i to the line that caused the error (the 'config' line)
                        # before attempting to skip the whole block.
                        self.i = original_line_index 
                        if not self._skip_to_next_block_or_end():
                             print(f"FATAL: Recovery failed. Could not find next block after error at line {original_line_index + 1}. Stopping parse.", file=sys.stderr)
                             return self.model # Return partially parsed model
                        print(f"Recovered: Skipped to line {self.i + 1}.", file=sys.stderr)
                else:
                    # No specific handler found, use generic (which also calls _read_block/_read_settings)
                    if self.debug: print(f"[L{original_line_index+1}] Using generic handler for section '{raw_section_name}'", file=sys.stderr) # DEBUG
                    try:
                        # Generic handler needs the content start index to know where to read from
                        self._handle_generic_section(raw_section_name, normalized_section_name, start_block_content_index)
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
                # Or potentially the 'end' for 'config global' if it doesn't contain nested blocks
                if self.current_vdom == 'global':
                    if self.debug: print(f"[L{original_line_index+1}] Found 'end' for global config.") # DEBUG
                    self.current_vdom = None # Exit global context
                    self.i += 1
                    last_successful_line = self.i
                    continue
                else:
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
        # Assumes 'config vdom' line was already consumed, self.i points to the next line.
        vdom_block_start_line = self.i # For debug
        self.model.has_vdoms = True # Mark VDOMs enabled

        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            original_line_index = self.i
            
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

                # Loop for lines within the 'edit <vdom_name>' block
                while self.i < len(self.lines):
                    inner_line = self.lines[self.i].strip()
                    inner_line_index = self.i

                    # Check for end of this VDOM entry ('next') or end of entire VDOM block ('end')
                    if self.NEXT_RE.match(inner_line):
                        self.i += 1
                        break # Exit inner loop, go to next VDOM edit or VDOM end
                    if self.END_RE.match(inner_line): # If 'end' found here, it terminates the whole 'config vdom'
                        if self.debug: print(f"Found 'end' prematurely inside VDOM '{vdom_name}' at line {self.i+1}. Terminating VDOM parse.") # DEBUG
                        return # Exit handler completely

                    # Handle config sections inside the VDOM
                    m_section = self.SECTION_RE.match(inner_line)
                    if m_section:
                         raw_section_name = m_section.group(1).strip().replace('"', '') # Remove quotes
                         normalized_section_name = raw_section_name.lower().replace(' ', '_').replace('-', '_')
                         handler_method_name = self.SECTION_ALIASES.get(normalized_section_name) or f'_handle_{normalized_section_name}'
                         handler = getattr(self, handler_method_name, None)
                         
                         # --- Advance parser index PAST the 'config ...' line BEFORE calling handler ---
                         self.i += 1
                         start_block_content_index = self.i # Mark where the block's content starts

                         if handler:
                             try: 
                                 handler() # Handler calls read_block/read_settings
                             except Exception as e:
                                  print(f"ERROR: VDOM Handler {handler_method_name} failed for section '{raw_section_name}' in VDOM '{vdom_name}': {e}", file=sys.stderr)
                                  # Attempt recovery within VDOM context
                                  self.i = inner_line_index # Reset to 'config' line
                                  if not self._skip_to_next_block_or_end(): # Try skipping the failed block
                                      print(f"FATAL: Recovery failed within VDOM '{vdom_name}'. Skipping rest of VDOM.", file=sys.stderr)
                                      # How to cleanly break to the next 'edit' or 'end'?
                                      # Search for 'next' or 'end' from current position
                                      found_next_or_end = False
                                      while self.i < len(self.lines):
                                          scan_line = self.lines[self.i].strip()
                                          if self.NEXT_RE.match(scan_line):
                                              self.i += 1; found_next_or_end = True; break
                                          if self.END_RE.match(scan_line):
                                              # Don't consume end here, let outer loop handle it
                                              found_next_or_end = True; break 
                                          self.i += 1
                                      if found_next_or_end: break # Break inner VDOM loop
                                      else: return # Reached EOF during VDOM recovery, exit handler
                                  else:
                                      print(f"Recovered within VDOM: Skipped to line {self.i + 1}.", file=sys.stderr)
                                      # Continue inner VDOM loop from the recovered position
                         else:
                              # Generic handler for sections inside VDOM
                              self._handle_generic_section(raw_section_name, normalized_section_name, start_block_content_index)
                         continue # Continue inner VDOM loop after handling section

                    # Skip comments/empty lines within VDOM entry
                    if not inner_line or inner_line.startswith('#'):
                         self.i += 1
                         continue
                         
                    # Handle unexpected lines within VDOM entry
                    print(f"Warning: Skipping unexpected line inside VDOM '{self.current_vdom}' entry at line {self.i+1}: {inner_line}", file=sys.stderr)
                    self.i += 1 
                # End of inner VDOM loop (after 'next' or recovery skip)
            
            # Skip comments/empty lines directly under 'config vdom'
            elif not line or line.startswith('#'):
                 self.i += 1
                 continue
            
            # Handle unexpected lines directly under 'config vdom' (e.g., before first 'edit')
            else:
                print(f"Warning: Skipping unexpected line inside 'config vdom' block at line {self.i+1}: {line}", file=sys.stderr)
                self.i += 1

        print("Warning: Reached end of file while inside 'config vdom' block.", file=sys.stderr)
        self.current_vdom = None # Clear context
        
    # --- Value Parsing Helper ---
    def _parse_set_value(self, key, raw_val, line_num):
        """Parses the value string from a 'set' command."""
        # Reuse the robust value parsing logic
        if raw_val.startswith('"') and raw_val.endswith('"'):
            # Handle edge case of empty quoted string "" -> empty string
            val = raw_val[1:-1] 
        elif ' ' in raw_val:
            # Try splitting respecting quotes
            split_vals = []
            current_val = ''
            in_quotes = False
            escape = False
            for char in raw_val:
                if char == '\\' and not escape:
                    escape = True # Next char is escaped
                elif char == '"' and not escape:
                    in_quotes = not in_quotes
                    # Keep quotes as part of the value if they are internal?
                    # For now, let's strip leading/trailing quotes later if needed.
                    current_val += char 
                elif char == ' ' and not in_quotes:
                    if current_val: # Append if non-empty
                        # Strip surrounding quotes from the completed value segment if present
                        if current_val.startswith('"') and current_val.endswith('"'):
                             split_vals.append(current_val[1:-1])
                        else:
                             split_vals.append(current_val)
                    current_val = ''
                else:
                    current_val += char
                    escape = False # Reset escape flag
            if current_val: # Append the last part
                # Strip surrounding quotes from the last segment
                if current_val.startswith('"') and current_val.endswith('"'):
                     split_vals.append(current_val[1:-1])
                else:
                     split_vals.append(current_val)

            # Handle specific key cases after splitting
            if key in ['ip', 'subnet'] and len(split_vals) == 2:
                ip_part, mask_part = split_vals[0], split_vals[1]
                try:
                    prefix = self._mask_to_prefix(mask_part)
                    if prefix is not None:
                        ipaddress.ip_address(ip_part) # Validate IP
                        val = f"{ip_part}/{prefix}"
                    else:
                        # Mask conversion failed, store as is
                        val = f"{ip_part}/{mask_part}" # Store original mask if invalid
                except ValueError: # Invalid IP address
                    print(f"Warning [Line {line_num}]: Invalid IP address format '{ip_part}' in '{ip_part} {mask_part}' for key '{key}'. Storing as is.", file=sys.stderr)
                    val = f"{ip_part}/{mask_part}"
            elif len(split_vals) > 1:
                # Multiple values after splitting, treat as list
                val = split_vals
            else:
                # Only one value after splitting (might contain spaces if quotes were weird)
                # Strip surrounding quotes if they remain
                single_val = split_vals[0] if split_vals else raw_val # Fallback to raw_val if split failed
                if single_val.startswith('"') and single_val.endswith('"'):
                     val = single_val[1:-1]
                else:
                     val = single_val
        else:
            # Simple single value, no spaces or quotes
            val = raw_val
        return val
        
    # --- Block Reading Helpers (with fallback) --- 

    def _read_block(self):
        """Read a block of settings for a list-based config section (e.g., firewall policy).
           Includes fallback to iterative parsing if recursion depth is exceeded.
        """
        block_start_line_index = self.i # Store starting line index (points to first line *after* 'config ...')
        try:
            # --- Original Recursive Logic ---
            items = []
            current_item = None
            nesting_level = 1
            if self.debug: print(f" >> Enter _read_block (Recursive) @ L{block_start_line_index+1}, Level {nesting_level}")

            while self.i < len(self.lines):
                line = self.lines[self.i].strip()
                original_line_index = self.i # Track line for error messages
                if self.debug: print(f"    [L{self.i+1}, Lvl {nesting_level}] Read: {line}")
                current_item_id = current_item.get('id', current_item.get('name', 'None')) if current_item else 'None'

                # Handle nested config blocks first
                if line.startswith('config '):
                     nesting_level += 1
                     match_nested_section = self.SECTION_RE.match(line)
                     if match_nested_section: nested_section_name = match_nested_section.group(1).strip().replace('"', '')
                     else: 
                          print(f"Warning [Line {original_line_index+1}]: Could not parse nested section name: {line}", file=sys.stderr)
                          nested_section_name = line.split(None, 1)[1].strip() if len(line.split()) > 1 else "unknown_nested"
                     nested_key = nested_section_name.lower().replace(' ','_').replace('-','_')

                     # Advance past nested 'config' line before recursive call
                     self.i += 1 
                     
                     peek_i = self.i; is_list_block = False
                     while peek_i < len(self.lines):
                         peek_line = self.lines[peek_i].strip(); peek_i += 1
                         if not peek_line or peek_line.startswith('#'): continue
                         if self.EDIT_RE.match(peek_line): is_list_block = True
                         break

                     # --- Recursive Call ---
                     if is_list_block: nested_data = self._read_block() # <<< RECURSION
                     else: nested_data = self._read_settings() # <<< RECURSION
                     # --- End Recursive Call ---

                     nesting_level -= 1 # Decrement level after recursive call returns
                     if current_item is not None: 
                          # Check if key already exists (e.g., multiple 'config members' blocks)
                          if nested_key in current_item:
                               # If existing value is not a list, make it one
                               if not isinstance(current_item[nested_key], list):
                                    current_item[nested_key] = [current_item[nested_key]]
                               # Append new data (assuming nested_data is a list or dict)
                               current_item[nested_key].append(nested_data) 
                          else:
                              current_item[nested_key] = nested_data
                     else: 
                          # Nested config outside an 'edit' item - unusual
                          print(f"Warning [Line {original_line_index+1}]: Nested config block '{nested_section_name}' found outside an 'edit' item. Storing may be ambiguous.", file=sys.stderr)
                     
                     # self.i was advanced by recursive call, so continue main loop
                     continue 

                m_edit = self.EDIT_RE.match(line)
                m_set = self.SET_RE.match(line)
                m_append = self.APPEND_RE.match(line)
                m_unset = self.UNSET_RE.match(line)
                m_next = self.NEXT_RE.match(line)
                m_end = self.END_RE.match(line)

                if m_edit:
                    if current_item is not None:
                        items.append(current_item) # Save previous item
                    edit_val = m_edit.group(1) or m_edit.group(2) # Quoted or unquoted name
                    id_key = 'id' if edit_val.isdigit() else 'name'
                    current_item = {id_key: edit_val}
                elif m_set and current_item is not None:
                    key = m_set.group(1).replace('-', '_') # Normalize key
                    raw_val = m_set.group(2).strip()     # Get the raw value part
                    val = self._parse_set_value(key, raw_val, original_line_index + 1) # Use helper
                    current_item[key] = val
                elif m_append and current_item is not None:
                     key = m_append.group(1).replace('-', '_'); raw_val = m_append.group(2).strip()
                     # Simple append value parsing for now (treat as string)
                     if raw_val.startswith('"') and raw_val.endswith('"'): append_val = raw_val[1:-1]
                     else: append_val = raw_val
                     # Ensure key exists as a list and append
                     if key not in current_item: current_item[key] = []
                     elif not isinstance(current_item[key], list): current_item[key] = [current_item[key]]
                     current_item[key].append(append_val)
                elif m_unset and current_item is not None:
                     key = m_unset.group(1).replace('-', '_')
                     if key in current_item: del current_item[key] # Remove the key
                elif m_next:
                     if current_item is not None: items.append(current_item)
                     current_item = None # Reset for the next item
                elif m_end:
                     nesting_level -= 1
                     if self.debug: print(f"       -> Found 'end', level -> {nesting_level}") # DEBUG
                     if nesting_level == 0:
                         if current_item is not None: items.append(current_item) # Append the last item
                         self.i += 1 # Consume 'end'
                         if self.debug: print(f" << Exit _read_block (Rec, found final end) @ L{self.i}, Lvl {nesting_level}")
                         return items # Return list of parsed items
                     # else: This 'end' closes a nested block handled earlier. Just let loop continue.
                elif not line or line.startswith('#'):
                     pass # Skip comments and empty lines
                else:
                     # Handle unexpected lines
                     print(f"Warning [Line {original_line_index + 1}]: Skipping unexpected line inside recursive block for item '{current_item_id}': {line}", file=sys.stderr)

                # Only advance if not continuing after nested block
                if not line.startswith('config '):
                     self.i += 1 # Move to the next line

            # End of loop (likely reached EOF)
            print(f"Warning: Reached end of file while reading block (Rec, nesting level {nesting_level}). Block started near {block_start_line_index+1}", file=sys.stderr)
            if current_item is not None:
                items.append(current_item) # Append the last item if loop terminated abruptly
            if self.debug: print(f" << Exit _read_block (Rec, EOF) @ L{self.i}, Lvl {nesting_level}")
            return items
            # --- End Original Recursive Logic ---

        except RecursionError:
            print(f"Warning: Recursion depth limit exceeded while parsing block starting near line {block_start_line_index}. Falling back to iterative parsing.", file=sys.stderr)
            # Reset parser position to the start of the block's content
            self.i = block_start_line_index 
            return self._read_block_iterative(block_start_line_index) # Call iterative version
        except Exception as e:
             print(f"ERROR during recursive _read_block near line {self.i+1} (started {block_start_line_index+1}): {e}", file=sys.stderr)
             raise # Re-raise other exceptions

    def _read_settings(self):
        """Read a block of settings for a single-item config section (e.g., system dns).
           Includes fallback to iterative parsing if recursion depth is exceeded.
        """
        block_start_line_index = self.i # Store starting line index (points to first line *after* 'config ...')
        try:
            # --- Original Recursive Logic ---
            settings = {}
            nesting_level = 1
            if self.debug: print(f" >> Enter _read_settings (Recursive) @ L{block_start_line_index+1}, Level {nesting_level}")

            while self.i < len(self.lines):
                line = self.lines[self.i].strip()
                original_line_index = self.i # Track line for error messages
                if self.debug: print(f"    [L{self.i+1}, Lvl {nesting_level}] Read: {line}")

                # Handle nested config blocks first
                if line.startswith('config '):
                     nesting_level += 1
                     match_nested_section = self.SECTION_RE.match(line)
                     if match_nested_section: nested_section_name = match_nested_section.group(1).strip().replace('"', '')
                     else: 
                          print(f"Warning [Line {original_line_index+1}]: Could not parse nested section name: {line}", file=sys.stderr)
                          nested_section_name = line.split(None, 1)[1].strip() if len(line.split()) > 1 else "unknown_nested"
                     nested_key = nested_section_name.lower().replace(' ','_').replace('-','_')
                     
                     # Advance past nested 'config' line before recursive call
                     self.i += 1 

                     peek_i = self.i; is_list_block = False
                     while peek_i < len(self.lines):
                         peek_line = self.lines[peek_i].strip(); peek_i += 1
                         if not peek_line or peek_line.startswith('#'): continue
                         if self.EDIT_RE.match(peek_line): is_list_block = True
                         break

                     # --- Recursive Call ---
                     if is_list_block: nested_data = self._read_block() # <<< RECURSION
                     else: nested_data = self._read_settings() # <<< RECURSION
                     # --- End Recursive Call ---

                     nesting_level -= 1 # Decrement level after recursive call returns
                     # Store nested data under the normalized key
                     # Handle multiple nested blocks with same name (e.g., 'config entries')
                     if nested_key in settings:
                          if not isinstance(settings[nested_key], list):
                               settings[nested_key] = [settings[nested_key]]
                          settings[nested_key].append(nested_data)
                     else:
                         settings[nested_key] = nested_data
                     
                     # self.i was advanced by recursive call, so continue main loop
                     continue 

                m_set = self.SET_RE.match(line)
                m_append = self.APPEND_RE.match(line)
                m_unset = self.UNSET_RE.match(line)
                m_end = self.END_RE.match(line)

                if m_set:
                    key = m_set.group(1).replace('-', '_') # Normalize key
                    raw_val = m_set.group(2).strip()     # Get the raw value part
                    val = self._parse_set_value(key, raw_val, original_line_index + 1) # Use helper
                    settings[key] = val
                elif m_append:
                     key = m_append.group(1).replace('-', '_'); raw_val = m_append.group(2).strip()
                     if raw_val.startswith('"') and raw_val.endswith('"'): append_val = raw_val[1:-1]
                     else: append_val = raw_val
                     # Ensure key exists as a list and append
                     if key not in settings: settings[key] = []
                     elif not isinstance(settings[key], list): settings[key] = [settings[key]]
                     settings[key].append(append_val)
                elif m_unset:
                     key = m_unset.group(1).replace('-', '_')
                     if key in settings: del settings[key] # Remove the key
                elif m_end:
                     nesting_level -= 1
                     if self.debug: print(f"       -> Found 'end', level -> {nesting_level}") # DEBUG
                     if nesting_level == 0:
                         self.i += 1 # Consume 'end'
                         if self.debug: print(f" << Exit _read_settings (Rec, found final end) @ L{self.i}, Lvl {nesting_level}")
                         return settings # Return the dictionary of settings
                     # else: This 'end' closes a nested block. Let loop continue.
                elif not line or line.startswith('#'):
                     pass # Skip comments and empty lines
                else:
                     # Handle unexpected lines
                     print(f"Warning [Line {original_line_index + 1}]: Skipping unexpected line inside recursive settings block: {line}", file=sys.stderr)

                # Only advance if not continuing after nested block
                if not line.startswith('config '):
                    self.i += 1 # Move to the next line

            # End of loop (likely reached EOF)
            print(f"Warning: Reached end of file while reading settings (Rec, nesting level {nesting_level}). Block started near {block_start_line_index+1}", file=sys.stderr)
            if self.debug: print(f" << Exit _read_settings (Rec, EOF) @ L{self.i}, Lvl {nesting_level}")
            return settings
            # --- End Original Recursive Logic ---

        except RecursionError:
            print(f"Warning: Recursion depth limit exceeded while parsing settings block starting near line {block_start_line_index}. Falling back to iterative parsing.", file=sys.stderr)
            # Reset parser position to the start of the block's content
            self.i = block_start_line_index
            return self._read_settings_iterative(block_start_line_index) # Call iterative version
        except Exception as e:
             print(f"ERROR during recursive _read_settings near line {self.i+1} (started {block_start_line_index+1}): {e}", file=sys.stderr)
             raise # Re-raise other exceptions

    # --- Iterative Parsers (Fallback) ---

    def _read_block_iterative(self, block_start_line_index):
        """Iteratively read a block of settings for a list-based config section."""
        if self.debug: print(f" >> Enter _read_block_iterative @ L{block_start_line_index + 1}") # DEBUG
        
        items = []
        # Stack stores dictionaries representing the current parsing context.
        # Each dict has 'type' ('list_item', 'nested_list', 'nested_settings')
        # and 'data' (the list/dict being built or None for top level).
        # List contexts also store 'current_item'.
        stack = [{'type': 'list_item', 'data': items, 'current_item': None}] # Start with the main list context
        self.i = block_start_line_index # Ensure parser is at the start of the block content

        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            original_line_index = self.i
            
            # Get current context from stack top
            if not stack: # Should not happen if logic is correct
                 print(f"ERROR: Parser stack empty during iterative read near line {original_line_index+1}. Aborting block.", file=sys.stderr)
                 # Attempt recovery by finding next end? For now, just return what we have.
                 return items 
                 
            current_context = stack[-1]
            context_type = current_context['type']
            # Target dictionary for 'set'/'append'/'unset' depends on context
            target_dict_for_set = None
            if context_type in ['list_item', 'nested_list']:
                 target_dict_for_set = current_context.get('current_item')
            elif context_type == 'nested_settings':
                 target_dict_for_set = current_context.get('data')

            if self.debug: 
                 context_id_str = "N/A"
                 if target_dict_for_set:
                      context_id_str = target_dict_for_set.get('id', target_dict_for_set.get('name', '...'))
                 elif context_type == 'list_item': context_id_str = "TopLevelList"
                 elif context_type == 'nested_list': context_id_str = "NestedList"
                 elif context_type == 'nested_settings': context_id_str = "NestedSettings"
                 print(f"    [L{self.i+1}, StackLvl {len(stack)}] Iter Ctx: {context_type} ({context_id_str}) | Read: {line}") # DEBUG

            # --- Handle Block Control Commands ---
            
            # Handle nested config blocks
            if line.startswith('config '):
                match_nested_section = self.SECTION_RE.match(line)
                if match_nested_section:
                     nested_section_name = match_nested_section.group(1).strip().replace('"', '')
                     nested_key = nested_section_name.lower().replace(' ','_').replace('-','_')
                     
                     # Advance past 'config' line temporarily for peeking
                     self.i += 1 
                     peek_i = self.i; is_nested_list = False
                     while peek_i < len(self.lines):
                         peek_line = self.lines[peek_i].strip(); peek_i += 1
                         if not peek_line or peek_line.startswith('#'): continue
                         if self.EDIT_RE.match(peek_line): is_nested_list = True
                         break
                     # Reset self.i back to the 'config' line
                     self.i = original_line_index 

                     new_context_type = 'nested_list' if is_nested_list else 'nested_settings'
                     new_nested_data = [] if is_nested_list else {}
                     
                     # Store the nested structure in the parent context BEFORE pushing stack
                     if isinstance(target_dict_for_set, dict):
                          # Handle multiple nested blocks with same name
                          if nested_key in target_dict_for_set:
                               if not isinstance(target_dict_for_set[nested_key], list):
                                    target_dict_for_set[nested_key] = [target_dict_for_set[nested_key]]
                               target_dict_for_set[nested_key].append(new_nested_data)
                               # Problem: Which list/dict instance do we push to stack? The new one.
                               data_to_push = new_nested_data 
                          else:
                              target_dict_for_set[nested_key] = new_nested_data
                              data_to_push = new_nested_data
                     elif context_type == 'nested_list' and isinstance(current_context['data'], list):
                           # If the parent is a list, the nested config belongs to the current_item within that list
                           parent_item = current_context.get('current_item')
                           if isinstance(parent_item, dict):
                               if nested_key in parent_item: # Handle duplicates
                                    if not isinstance(parent_item[nested_key], list): parent_item[nested_key] = [parent_item[nested_key]]
                                    parent_item[nested_key].append(new_nested_data)
                               else: parent_item[nested_key] = new_nested_data
                               data_to_push = new_nested_data
                           else:
                               print(f"Warning [Line {original_line_index+1}]: Nested block '{nested_key}' found in list context, but no current item dictionary. Skipping.", file=sys.stderr)
                               self.i += 1; continue # Skip 'config' line
                     else:
                          # Adding nested block to unexpected parent type
                          print(f"Warning [Line {original_line_index+1}]: Trying to add nested block '{nested_key}' to non-dict parent context: {type(target_dict_for_set)}. Skipping nested block.", file=sys.stderr)
                          self.i += 1; continue # Skip 'config' line

                     # Push new context onto stack
                     new_context = {'type': new_context_type, 'data': data_to_push}
                     if is_nested_list: new_context['current_item'] = None # Init list item tracker
                     stack.append(new_context) 
                     if self.debug: print(f"       -> PUSH stack (nested config '{nested_key}', type {new_context_type}). New depth: {len(stack)}")
                     self.i += 1 # Consume 'config ...' line
                     continue # Process next line with the new context
                else:
                     print(f"Warning [Line {original_line_index+1}]: Malformed nested config line: {line}. Attempting to skip.", file=sys.stderr)
                     self.i += 1; continue

            # Handle 'edit' command (Only valid in list contexts)
            m_edit = self.EDIT_RE.match(line)
            if m_edit:
                if context_type in ['list_item', 'nested_list']:
                     # Finalize the previous item being built in this list context
                     list_to_append_to = current_context['data'] # The actual list object
                     item_being_built = current_context.get('current_item')
                     if item_being_built is not None and isinstance(list_to_append_to, list):
                          list_to_append_to.append(item_being_built)

                     # Start the new item
                     edit_val = m_edit.group(1) or m_edit.group(2)
                     id_key = 'id' if edit_val.isdigit() else 'name'
                     new_item = {id_key: edit_val}
                     # Update the stack context for the *current* list level
                     stack[-1]['current_item'] = new_item 
                     if self.debug: print(f"       -> Started new item: {new_item}")
                else:
                     print(f"Warning [Line {original_line_index+1}]: 'edit' command found in non-list context ('{context_type}'). Skipping line.", file=sys.stderr)
                self.i += 1; continue

            # Handle 'set' command
            m_set = self.SET_RE.match(line)
            if m_set:
                if isinstance(target_dict_for_set, dict):
                    key = m_set.group(1).replace('-', '_')
                    raw_val = m_set.group(2).strip()
                    val = self._parse_set_value(key, raw_val, original_line_index + 1) # Use helper
                    target_dict_for_set[key] = val
                    if self.debug: print(f"       -> Stored set in {context_type}: {key} = {val}")
                else:
                     context_id_str = "N/A"
                     if target_dict_for_set: context_id_str = target_dict_for_set.get('id', target_dict_for_set.get('name', '...'))
                     print(f"Warning [Line {original_line_index + 1}]: 'set' command encountered but no valid current item/dictionary in context ('{context_type}', item '{context_id_str}'). Skipping line.", file=sys.stderr)
                self.i += 1; continue

            # Handle 'append' command
            m_append = self.APPEND_RE.match(line)
            if m_append:
                if isinstance(target_dict_for_set, dict):
                     key = m_append.group(1).replace('-', '_'); raw_val = m_append.group(2).strip()
                     if raw_val.startswith('"') and raw_val.endswith('"'): append_val = raw_val[1:-1]
                     else: append_val = raw_val
                     if key not in target_dict_for_set: target_dict_for_set[key] = []
                     elif not isinstance(target_dict_for_set[key], list): target_dict_for_set[key] = [target_dict_for_set[key]]
                     target_dict_for_set[key].append(append_val)
                     if self.debug: print(f"       -> Handled append for key '{key}', value '{append_val}'")
                else:
                     print(f"Warning [Line {original_line_index+1}]: 'append' command encountered but no valid current item/dictionary in context ('{context_type}'). Skipping line.", file=sys.stderr)
                self.i += 1; continue

            # Handle 'unset' command
            m_unset = self.UNSET_RE.match(line)
            if m_unset:
                 if isinstance(target_dict_for_set, dict):
                     key = m_unset.group(1).replace('-', '_')
                     if key in target_dict_for_set: del target_dict_for_set[key]
                     if self.debug: print(f"       -> Handled unset for key '{key}'")
                 else:
                     print(f"Warning [Line {original_line_index+1}]: 'unset' command encountered but no valid current item/dictionary in context ('{context_type}'). Skipping line.", file=sys.stderr)
                 self.i += 1; continue

            # Handle 'next' command (Only valid in list contexts)
            m_next = self.NEXT_RE.match(line)
            if m_next:
                 if context_type in ['list_item', 'nested_list']:
                     # Finalize the current item and add it to the list in the context data
                     list_to_append_to = current_context.get('data')
                     item_being_built = current_context.get('current_item')
                     if item_being_built is not None and isinstance(list_to_append_to, list):
                         list_to_append_to.append(item_being_built)
                         stack[-1]['current_item'] = None # Reset item for the next 'edit'
                         if self.debug: print(f"       -> Handled 'next', finalized item.")
                     else:
                         if self.debug: print(f"       -> Handled 'next', no current item to finalize or parent not list.")
                 else:
                     print(f"Warning [Line {original_line_index+1}]: 'next' command found in non-list context ('{context_type}'). Skipping line.", file=sys.stderr)
                 self.i += 1; continue

            # Handle 'end' command
            m_end = self.END_RE.match(line)
            if m_end:
                # Finalize the last item if we are ending a list context
                if context_type in ['list_item', 'nested_list']:
                     list_to_append_to = current_context.get('data')
                     item_being_built = current_context.get('current_item')
                     if item_being_built is not None and isinstance(list_to_append_to, list):
                         list_to_append_to.append(item_being_built)
                         if self.debug: print(f"       -> Finalized last item before 'end'.")

                # Pop context from stack
                stack.pop()
                if self.debug: print(f"       -> POP stack (found end). New depth: {len(stack)}")

                if not stack:
                     # Popped the last context, we're done with this block
                     self.i += 1 # Consume 'end'
                     if self.debug: print(f" << Exit _read_block_iterative (found final end) @ L{self.i}") # DEBUG
                     # The top-level 'data' in the initial context was the 'items' list itself
                     return items 
                else:
                     # Still inside nested blocks
                     self.i += 1 # Consume 'end'
                     continue
                
            # Handle comments and empty lines
            if not line or line.startswith('#'):
                self.i += 1; continue

            # Handle unexpected lines
            print(f"Warning [Line {original_line_index + 1}]: Skipping unexpected line inside iterative block reader: {line}", file=sys.stderr)
            self.i += 1

        # --- End of loop (EOF reached before final 'end') ---
        if stack:
             print(f"Warning: Reached end of file while reading block iteratively. Stack depth: {len(stack)}. Block started near {block_start_line_index+1}", file=sys.stderr)
             # Attempt to finalize the very last item if necessary
             if len(stack) == 1 and stack[0]['type'] == 'list_item':
                 final_context = stack[0]
                 item_being_built = final_context.get('current_item')
                 if item_being_built is not None:
                      items.append(item_being_built)

        if self.debug: print(f" << Exit _read_block_iterative (EOF) @ L{self.i}") # DEBUG
        return items

    def _read_settings_iterative(self, block_start_line_index):
        """Iteratively read a block of settings for a single-item config section."""
        if self.debug: print(f" >> Enter _read_settings_iterative @ L{block_start_line_index + 1}") # DEBUG

        top_level_settings = {}
        # Stack stores dictionaries: {'type': 'settings'/'nested_list'/'nested_settings', 'data': dict/list, 'current_item': dict/None}
        stack = [{'type': 'settings', 'data': top_level_settings}] 
        self.i = block_start_line_index # Ensure parser is at the start

        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            original_line_index = self.i
            
            if not stack: # Should not happen
                 print(f"ERROR: Parser stack empty during iterative settings read near line {original_line_index+1}. Aborting block.", file=sys.stderr)
                 return top_level_settings

            current_context = stack[-1]
            context_type = current_context['type']
            # Target dictionary for 'set'/'append'/'unset' depends on context
            target_dict_for_set = None
            if context_type in ['settings', 'nested_settings']:
                 target_dict_for_set = current_context.get('data')
            elif context_type == 'nested_list':
                 target_dict_for_set = current_context.get('current_item')

            if self.debug: print(f"    [L{self.i+1}, StackLvl {len(stack)}] Iter Ctx: {context_type} | Read: {line}") # DEBUG

            # Handle nested config blocks
            if line.startswith('config '):
                match_nested_section = self.SECTION_RE.match(line)
                if match_nested_section:
                     nested_section_name = match_nested_section.group(1).strip().replace('"', '')
                     nested_key = nested_section_name.lower().replace(' ','_').replace('-','_')
                     
                     # Advance past 'config' line temporarily for peeking
                     self.i += 1 
                     peek_i = self.i; is_nested_list = False
                     while peek_i < len(self.lines):
                         peek_line = self.lines[peek_i].strip(); peek_i += 1
                         if not peek_line or peek_line.startswith('#'): continue
                         if self.EDIT_RE.match(peek_line): is_nested_list = True
                         break
                     self.i = original_line_index # Reset self.i

                     new_context_type = 'nested_list' if is_nested_list else 'nested_settings'
                     new_nested_data = [] if is_nested_list else {}
                     
                     # Store nested data in the parent dictionary context
                     if isinstance(target_dict_for_set, dict):
                          if nested_key in target_dict_for_set: # Handle duplicates
                               if not isinstance(target_dict_for_set[nested_key], list): target_dict_for_set[nested_key] = [target_dict_for_set[nested_key]]
                               target_dict_for_set[nested_key].append(new_nested_data)
                               data_to_push = new_nested_data # Push the new instance
                          else:
                              target_dict_for_set[nested_key] = new_nested_data
                              data_to_push = new_nested_data
                     elif context_type == 'nested_list' and isinstance(current_context['data'], list):
                           # Nested config inside a list item within settings
                           parent_item = current_context.get('current_item')
                           if isinstance(parent_item, dict):
                               if nested_key in parent_item: # Handle duplicates
                                    if not isinstance(parent_item[nested_key], list): parent_item[nested_key] = [parent_item[nested_key]]
                                    parent_item[nested_key].append(new_nested_data)
                               else: parent_item[nested_key] = new_nested_data
                               data_to_push = new_nested_data
                           else:
                               print(f"Warning [Line {original_line_index+1}]: Nested block '{nested_key}' found in list context, but no current item dictionary. Skipping.", file=sys.stderr)
                               self.i += 1; continue # Skip 'config' line
                     else: 
                          print(f"Warning [Line {original_line_index+1}]: Trying to add nested block '{nested_key}' to non-dict parent context: {type(target_dict_for_set)} in settings block. Skipping nested block.", file=sys.stderr)
                          self.i += 1; continue # Skip 'config' line

                     # Push new context
                     new_context = {'type': new_context_type, 'data': data_to_push}
                     if is_nested_list: new_context['current_item'] = None
                     stack.append(new_context)
                     if self.debug: print(f"       -> PUSH stack (nested config '{nested_key}', type {new_context_type}). New depth: {len(stack)}")
                     self.i += 1; continue # Consume 'config' line
                else:
                     print(f"Warning [Line {original_line_index+1}]: Malformed nested config line: {line}. Attempting to skip.", file=sys.stderr)
                     self.i += 1; continue

            # Handle 'edit' (Only valid if inside a 'nested_list' context)
            m_edit = self.EDIT_RE.match(line)
            if m_edit:
                 if context_type == 'nested_list':
                     list_to_append_to = current_context['data']
                     item_being_built = current_context.get('current_item')
                     if item_being_built is not None and isinstance(list_to_append_to, list):
                          list_to_append_to.append(item_being_built)
                     
                     edit_val = m_edit.group(1) or m_edit.group(2)
                     id_key = 'id' if edit_val.isdigit() else 'name'
                     new_item = {id_key: edit_val}
                     stack[-1]['current_item'] = new_item # Store item being built in list context
                     if self.debug: print(f"       -> Started new item in nested list: {new_item}")
                 else:
                     print(f"Warning [Line {original_line_index+1}]: 'edit' command found in non-list context ('{context_type}') within settings block. Skipping line.", file=sys.stderr)
                 self.i += 1; continue

            # Handle 'set' command
            m_set = self.SET_RE.match(line)
            if m_set:
                 if isinstance(target_dict_for_set, dict):
                     key = m_set.group(1).replace('-', '_')
                     raw_val = m_set.group(2).strip()
                     val = self._parse_set_value(key, raw_val, original_line_index + 1)
                     target_dict_for_set[key] = val
                     if self.debug: print(f"       -> Stored set in {context_type}: {key} = {val}")
                 else:
                     print(f"Warning [Line {original_line_index + 1}]: 'set' command encountered but no valid current dictionary in context ('{context_type}'). Skipping line.", file=sys.stderr)
                 self.i += 1; continue

            # Handle 'append' command
            m_append = self.APPEND_RE.match(line)
            if m_append:
                 if isinstance(target_dict_for_set, dict):
                     key = m_append.group(1).replace('-', '_'); raw_val = m_append.group(2).strip()
                     if raw_val.startswith('"') and raw_val.endswith('"'): append_val = raw_val[1:-1]
                     else: append_val = raw_val
                     if key not in target_dict_for_set: target_dict_for_set[key] = []
                     elif not isinstance(target_dict_for_set[key], list): target_dict_for_set[key] = [target_dict_for_set[key]]
                     target_dict_for_set[key].append(append_val)
                     if self.debug: print(f"       -> Handled append for key '{key}', value '{append_val}'")
                 else:
                     print(f"Warning [Line {original_line_index+1}]: 'append' command encountered but no valid dictionary in context ('{context_type}'). Skipping line.", file=sys.stderr)
                 self.i += 1; continue

            # Handle 'unset' command
            m_unset = self.UNSET_RE.match(line)
            if m_unset:
                 if isinstance(target_dict_for_set, dict):
                     key = m_unset.group(1).replace('-', '_')
                     if key in target_dict_for_set: del target_dict_for_set[key]
                     if self.debug: print(f"       -> Handled unset for key '{key}'")
                 else:
                     print(f"Warning [Line {original_line_index+1}]: 'unset' command encountered but no valid dictionary in context ('{context_type}'). Skipping line.", file=sys.stderr)
                 self.i += 1; continue

            # Handle 'next' command (Only valid in 'nested_list' context)
            m_next = self.NEXT_RE.match(line)
            if m_next:
                 if context_type == 'nested_list':
                     list_to_append_to = current_context.get('data')
                     item_being_built = current_context.get('current_item')
                     if item_being_built is not None and isinstance(list_to_append_to, list):
                         list_to_append_to.append(item_being_built)
                         stack[-1]['current_item'] = None # Reset item for next 'edit'
                         if self.debug: print(f"       -> Handled 'next' in nested list.")
                     else:
                          if self.debug: print(f"       -> Handled 'next', no current item to finalize or parent not list.")
                 else:
                     print(f"Warning [Line {original_line_index+1}]: 'next' command found in non-list context ('{context_type}') within settings. Skipping line.", file=sys.stderr)
                 self.i += 1; continue

            # Handle 'end' command
            m_end = self.END_RE.match(line)
            if m_end:
                # Finalize the last item if we are ending a nested list context
                if context_type == 'nested_list':
                     list_to_append_to = current_context.get('data')
                     item_being_built = current_context.get('current_item')
                     if item_being_built is not None and isinstance(list_to_append_to, list):
                         list_to_append_to.append(item_being_built)
                         if self.debug: print(f"       -> Finalized last item in nested list before 'end'.")

                stack.pop()
                if self.debug: print(f"       -> POP stack (found end). New depth: {len(stack)}")

                if not stack:
                     self.i += 1 # Consume final 'end'
                     if self.debug: print(f" << Exit _read_settings_iterative (found final end) @ L{self.i}") # DEBUG
                     return top_level_settings
                else:
                     self.i += 1 # Consume 'end'
                     continue

            # Handle comments/empty lines
            if not line or line.startswith('#'):
                self.i += 1; continue

            # Handle unexpected lines
            print(f"Warning [Line {original_line_index + 1}]: Skipping unexpected line inside iterative settings reader: {line}", file=sys.stderr)
            self.i += 1

        # --- End of loop (EOF) ---
        if stack:
             print(f"Warning: Reached end of file while reading settings iteratively. Stack depth: {len(stack)}. Block started near {block_start_line_index+1}", file=sys.stderr)
             # No item finalization needed here as the top level is a dict

        if self.debug: print(f" << Exit _read_settings_iterative (EOF) @ L{self.i}") # DEBUG
        return top_level_settings

    # --- Specific Section Handlers --- 
    # These methods parse specific 'config ...' sections.
    # They typically call _read_block() or _read_settings() and store the result
    # in the appropriate attribute of the self.model or VDOM sub-model.
    # **IMPORTANT**: These handlers should now be called AFTER the main loop
    # has consumed the 'config ...' line that identifies the section.

    def _get_target_model(self):
         """Returns the correct model (main or VDOM) based on current_vdom."""
         if self.current_vdom and self.current_vdom != 'global' and self.current_vdom in self.model.vdoms:
             return self.model.vdoms[self.current_vdom]
         else:
             # Use main model for global, root, or if VDOM context is missing/invalid
             return self.model 
             
    def _handle_router_static(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        processed_routes = []
        for idx, item in enumerate(items):
             # Ensure item is a dictionary before processing
             if not isinstance(item, dict):
                  print(f"Warning [Handler:router_static]: Expected dict for route item, got {type(item)}. Skipping.", file=sys.stderr)
                  continue
                  
             # Use seq_num if present, otherwise generate name
             item['name'] = item.get('seq_num', f'static_route_{idx+1}') 
             
             # --- Convert dst list [ip, mask] to ip/prefix string ---
             dst_val = item.get('dst')
             if isinstance(dst_val, list) and len(dst_val) == 2:
                 ip_part = dst_val[0]
                 mask_part = dst_val[1]
                 prefix = self._mask_to_prefix(mask_part)
                 if prefix is not None:
                     try:
                         ipaddress.ip_address(ip_part) # Validate IP
                         item['dst'] = f"{ip_part}/{prefix}"
                     except ValueError:
                          print(f"Warning [Handler:router_static]: Invalid IP '{ip_part}' in route destination '{item['name']}'. Storing as ip/mask.", file=sys.stderr)
                          item['dst'] = f"{ip_part}/{mask_part}" 
                 else:
                     # Fallback to ip/mask if prefix conversion failed
                     item['dst'] = f"{ip_part}/{mask_part}" 
                     # Warning printed in _mask_to_prefix
             elif isinstance(dst_val, list): # Unexpected list format
                 print(f"Warning [Handler:router_static]: Unexpected list format for destination in route '{item['name']}': {dst_val}. Storing as is.", file=sys.stderr)
             # else: dst_val is already a string or None, leave it as is
             
             processed_routes.append(item) # Add the potentially modified item
             
        target_model.routes.extend(processed_routes)

    def _handle_firewall_address(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:firewall_address]: Expected dict for address item, got {type(item)}. Skipping.", file=sys.stderr)
                continue # Skip non-dict items
            name = item.get('name')
            if name:
                # Normalize address types
                addr_type = item.get('type', 'ipmask') # Default type? Check FortiOS defaults
                if addr_type == 'ipmask' and 'subnet' in item:
                    pass # Already handled by _parse_set_value likely
                elif addr_type == 'fqdn':
                     item['subnet'] = item.get('fqdn', item.get('name')) # Store FQDN in subnet field for consistency?
                elif addr_type == 'wildcard':
                     # Store wildcard address - needs specific handling later
                     item['subnet'] = item.get('wildcard', '?/?') 
                elif addr_type == 'iprange':
                     item['subnet'] = f"{item.get('start_ip','?')}-{item.get('end_ip','?')}" # Combine range
                elif addr_type == 'geography':
                     item['subnet'] = f"geo:{item.get('country', '?')}" # Store geography info
                elif addr_type == 'interface-subnet':
                     item['subnet'] = f"if-subnet:{item.get('subnet', name)}" # Reference to interface subnet

                target_model.addresses[name] = item
            else:
                 print(f"Warning [Handler:firewall_address]: Address item found without name near line ~{self.i}. Skipping.", file=sys.stderr)
                 
    def _handle_firewall_addrgrp(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:firewall_addrgrp]: Expected dict for addrgrp item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            members = item.get('member', [])
            if name:
                # Ensure members is always a list
                target_model.addr_groups[name] = members if isinstance(members, list) else [members]
            else:
                 print(f"Warning [Handler:firewall_addrgrp]: Address group found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_firewall_service_custom(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:service_custom]: Expected dict for service item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                protocol = item.get('protocol', 'TCP/UDP/SCTP') # Default protocol
                # Combine port ranges into a single 'port' field for simplicity
                port_info = []
                if 'tcp_portrange' in item: port_info.append(f"TCP:{item['tcp_portrange']}")
                if 'udp_portrange' in item: port_info.append(f"UDP:{item['udp_portrange']}")
                if 'sctp_portrange' in item: port_info.append(f"SCTP:{item['sctp_portrange']}")
                
                if protocol == 'ICMP' or protocol == 'ICMP6':
                     icmp_type = item.get('icmptype', 'any')
                     icmp_code = item.get('icmpcode', 'any') if icmp_type != 'any' else 'any'
                     port_info.append(f"Type:{icmp_type}" + (f"/Code:{icmp_code}" if icmp_code != 'any' else ""))
                     item['protocol'] = protocol.upper() # Ensure consistent case
                elif protocol == 'IP':
                     port_info.append(f"ProtoNum:{item.get('protocol_number','any')}")
                     item['protocol'] = 'IP'
                elif protocol == 'TCP/UDP/SCTP':
                    # Handled by tcp/udp/sctp_portrange above
                    pass
                else:
                     # Fallback for less common protocols
                     port_info.append(f"{protocol}:{item.get(f'{protocol.lower()}_portrange', 'any')}")
                     
                item['port'] = ', '.join(port_info) if port_info else 'any'
                     
                target_model.services[name] = item
            else:
                 print(f"Warning [Handler:service_custom]: Custom service found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_firewall_service_group(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:service_group]: Expected dict for svcgrp item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            members = item.get('member', [])
            if name:
                target_model.svc_groups[name] = members if isinstance(members, list) else [members]
            else:
                 print(f"Warning [Handler:service_group]: Service group found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_firewall_policy(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        multi_value_keys = ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service']
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:firewall_policy]: Expected dict for policy item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            # Use 'policyid' if present, fall back to 'id' (less common)
            item['id'] = item.get('policyid', item.get('id')) 
            if not item.get('id'): 
                print(f"Warning [Handler:firewall_policy]: Policy found without ID (policyid) near line {self.i}. Skipping.", file=sys.stderr)
                continue
                
            # Ensure multi-value fields are lists
            for key in multi_value_keys:
                 # Use get to avoid KeyError if key is missing
                 current_val = item.get(key)
                 if current_val is not None and not isinstance(current_val, list):
                     item[key] = [current_val]
                 elif current_val is None: # Ensure key exists even if empty
                      item[key] = [] 
                      
            item['comments'] = item.get('comments', '') # Ensure comments field exists
            target_model.policies.append(item)
            
    _handle_firewall_policy6 = _handle_firewall_policy # Alias for IPv6 policies

    def _handle_system_interface(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:system_interface]: Expected dict for interface item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                 # Handle secondary IPs (might be nested block or simple list?)
                 # Assuming _read_block handles nested 'secondaryip' correctly
                 secondary_ips_raw = item.get('secondaryip', [])
                 item['secondary_ip'] = []
                 if isinstance(secondary_ips_raw, list):
                     # If it's a list of dicts (from nested config)
                     if all(isinstance(sip, dict) for sip in secondary_ips_raw):
                          item['secondary_ip'] = [sip.get('ip','?') for sip in secondary_ips_raw]
                     # If it's already a list of strings (from simple set/append?)
                     elif all(isinstance(sip, str) for sip in secondary_ips_raw):
                          item['secondary_ip'] = secondary_ips_raw
                 elif isinstance(secondary_ips_raw, dict): # Single nested item
                      item['secondary_ip'] = [secondary_ips_raw.get('ip','?')]
                 
                 # Ensure description exists
                 item['description'] = item.get('description', '') 
                      
                 target_model.interfaces[name] = item
            else:
                 print(f"Warning [Handler:system_interface]: System interface found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    # Example handler for VLANs if they are under 'system vlan'
    def _handle_system_vlan_interface(self): 
        # This might be needed if 'config system vlan-interface' exists
        print("Info: Parsing 'config system vlan-interface'. Treating as regular interfaces.", file=sys.stderr)
        self._handle_system_interface() # Reuse interface logic

    def _handle_switch_controller_managed_switch(self):
        print("Warning: Skipping complex section 'switch-controller managed-switch'. Parsing not fully implemented.", file=sys.stderr)
        # Need robust skipping if not parsing
        self.i = self.current_block_start_index # Reset to start of block content
        self._skip_to_next_block_or_end() # Use recovery skip

    def _handle_switch_controller_vlan(self): 
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:switch_vlan]: Expected dict for switch vlan item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                 members_raw = item.get('member', []) # Might be nested block
                 item['members'] = []
                 if isinstance(members_raw, list):
                     item['members'] = [m.get('interface_name','?') for m in members_raw if isinstance(m, dict)]
                 elif isinstance(members_raw, dict): # Single member
                      item['members'] = [members_raw.get('interface_name','?')]
                      
                 target_model.vlans[name] = item # Store under 'vlans' model attribute
            else:
                print(f"Warning [Handler:switch_vlan]: Switch controller VLAN found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_zone(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:system_zone]: Expected dict for zone item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            interfaces = item.get('interface', [])
            if name:
                # Ensure 'interface' is a list
                item['interface'] = interfaces if isinstance(interfaces, list) else [interfaces]
                target_model.zones[name] = item
            else:
                print(f"Warning [Handler:system_zone]: System zone found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_firewall_vip(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:firewall_vip]: Expected dict for VIP item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                # Handle mapped IPs (might be nested block)
                mapped_ips_raw = item.get('mappedip', [])
                item['mappedip_parsed'] = [] # Store parsed IPs here
                if isinstance(mapped_ips_raw, list):
                     if all(isinstance(mip, dict) for mip in mapped_ips_raw):
                          item['mappedip_parsed'] = [mip.get('range','?') for mip in mapped_ips_raw]
                     elif all(isinstance(mip, str) for mip in mapped_ips_raw): # Simple list? Unlikely
                           item['mappedip_parsed'] = mapped_ips_raw 
                elif isinstance(mapped_ips_raw, dict): # Single nested item
                      item['mappedip_parsed'] = [mapped_ips_raw.get('range','?')]
                      
                target_model.vips[name] = item
            else:
                print(f"Warning [Handler:firewall_vip]: Firewall VIP found without name near line ~{self.i}. Skipping.", file=sys.stderr)
                
    _handle_firewall_vip6 = _handle_firewall_vip # Alias for IPv6 VIPs

    def _handle_firewall_vipgrp(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:firewall_vipgrp]: Expected dict for VIP group item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            members = item.get('member', [])
            if name:
                target_model.vip_groups[name] = members if isinstance(members, list) else [members]
            else:
                print(f"Warning [Handler:firewall_vipgrp]: VIP group found without name near line ~{self.i}. Skipping.", file=sys.stderr)
                
    _handle_firewall_vipgrp6 = _handle_firewall_vipgrp # Alias for IPv6 VIP groups

    def _handle_firewall_ippool(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:firewall_ippool]: Expected dict for IP Pool item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                target_model.ippools[name] = item
            else:
                print(f"Warning [Handler:firewall_ippool]: IP Pool found without name near line ~{self.i}. Skipping.", file=sys.stderr)
                
    _handle_firewall_ippool6 = _handle_firewall_ippool # Alias for IPv6 IP Pools

    def _handle_system_dhcp_server(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:dhcp_server]: Expected dict for DHCP server item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             item_id = item.get('id') # DHCP servers use ID
             if not item_id:
                  print(f"Warning [Handler:dhcp_server]: DHCP Server found without ID near line ~{self.i}. Skipping.", file=sys.stderr)
                  continue
                  
             # Process IP range (usually a nested block 'config ip-range')
             ip_range_list = item.get('ip_range', [])
             if isinstance(ip_range_list, list) and ip_range_list:
                 ip_range_data = ip_range_list[0] # Assume only one range block per server ID
                 if isinstance(ip_range_data, dict):
                      item['ip_range_str'] = f"{ip_range_data.get('start_ip','?')} - {ip_range_data.get('end_ip','?')}"
                 else: item['ip_range_str'] = "Invalid Range Data"
             elif isinstance(ip_range_list, dict): # If parser returned single dict
                  item['ip_range_str'] = f"{ip_range_list.get('start_ip','?')} - {ip_range_list.get('end_ip','?')}"
             else: item['ip_range_str'] = "Not Configured"
                 
             # Handle nested 'config reserved-address' block
             # _read_block should store this as a list of dicts in item['reserved_address']
             reserved_list = item.get('reserved_address', [])
             item['reserved_addresses'] = reserved_list if isinstance(reserved_list, list) else [] # Ensure it's a list
                 
             target_model.dhcp_servers.append(item) # Store the whole item dict

    def _handle_router_ospf(self):
        target_model = self._get_target_model()
        # This is a settings block, not a list block
        settings = self._read_settings() # Use default iterative version
        target_model.ospf = settings if isinstance(settings, dict) else {} # Ensure it's a dict

    def _handle_router_bgp(self):
        target_model = self._get_target_model()
        settings = self._read_settings() # Use default iterative version
        
        if not isinstance(settings, dict):
            print(f"Warning [Handler:router_bgp]: Expected dict for BGP settings, got {type(settings)}. Skipping BGP parse.", file=sys.stderr)
            settings = {} # Assign empty dict to prevent errors
            
        # Extract known nested list sections if they exist
        target_model.bgp_neighbors = settings.pop('neighbor', []) if isinstance(settings.get('neighbor'), list) else []
        target_model.bgp_networks = settings.pop('network', []) if isinstance(settings.get('network'), list) else []
        # Add others like neighbor-group, neighbor-range etc. if needed
            
        # Store the remaining top-level BGP settings
        target_model.bgp = settings

    def _handle_vpn_ipsec_phase1_interface(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:vpn_p1]: Expected dict for P1 item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                target_model.phase1[name] = item
            else:
                print(f"Warning [Handler:vpn_p1]: VPN Phase1 found without name near line ~{self.i}. Skipping.", file=sys.stderr)
                
    _handle_vpn_ipsec_phase1 = _handle_vpn_ipsec_phase1_interface # Alias

    def _handle_vpn_ipsec_phase2_interface(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:vpn_p2]: Expected dict for P2 item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                target_model.phase2[name] = item
            else:
                print(f"Warning [Handler:vpn_p2]: VPN Phase2 found without name near line ~{self.i}. Skipping.", file=sys.stderr)
                
    _handle_vpn_ipsec_phase2 = _handle_vpn_ipsec_phase2_interface # Alias

    def _handle_firewall_shaper_traffic_shaper(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:traffic_shaper]: Expected dict for shaper item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                target_model.traffic_shapers[name] = item

    def _handle_firewall_shaper_per_ip_shaper(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:per_ip_shaper]: Expected dict for per-ip shaper item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                target_model.shaper_per_ip[name] = item

    def _handle_firewall_dos_policy(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        multi_keys = ['srcaddr', 'dstaddr', 'service']
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:dos_policy]: Expected dict for DoS policy item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            item['id'] = item.get('policyid', item.get('id')) # Uses policyid
            if not item['id']:
                 print(f"Warning [Handler:dos_policy]: DoS Policy found without ID (policyid) near line ~{self.i}. Skipping.", file=sys.stderr)
                 continue
            for key in multi_keys: # Ensure lists
                 current_val = item.get(key)
                 if current_val is not None and not isinstance(current_val, list):
                     item[key] = [current_val]
                 elif current_val is None:
                     item[key] = []
            target_model.dos_policies.append(item)
            
    _handle_firewall_dos_policy6 = _handle_firewall_dos_policy # Alias

    def _handle_system_snmp_sysinfo(self):
        target_model = self._get_target_model()
        settings = self._read_settings() # Use default iterative version
        target_model.snmp_sysinfo = settings if isinstance(settings, dict) else {}

    def _handle_system_snmp_community(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:snmp_community]: Expected dict for SNMP community item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            comm_id = item.get('id') # Uses ID
            if comm_id:
                 # Handle nested host/host6 blocks
                 hosts_raw = item.get('hosts', [])
                 item['hosts_parsed'] = [h.get('ip','?') for h in hosts_raw if isinstance(h, dict)] if isinstance(hosts_raw, list) else []
                 hosts6_raw = item.get('hosts6', [])
                 item['hosts6_parsed'] = [h.get('ipv6','?') for h in hosts6_raw if isinstance(h, dict)] if isinstance(hosts6_raw, list) else []
                 target_model.snmp_communities[comm_id] = item
            else:
                 print(f"Warning [Handler:snmp_community]: SNMP community found without ID near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_user_ldap(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:user_ldap]: Expected dict for LDAP item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                target_model.ldap_servers[name] = item
            else:
                print(f"Warning [Handler:user_ldap]: LDAP Server found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_admin(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:system_admin]: Expected dict for admin item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                 # Handle trusted hosts (can be multiple 'set trusthostX' lines)
                 item['trusted_hosts'] = []
                 for i in range(1, 11): # Check keys trusthost1 to trusthost10
                     th_key = f'trusthost{i}'
                     if th_key in item:
                         val = item.get(th_key) # Use get for safety
                         # Value might be 'ip mask' string or list [ip, mask] from parser
                         if isinstance(val, list) and len(val) == 2:
                             ip_part, mask_part = val[0], val[1]
                             # Special case: 0.0.0.0 0.0.0.0 means any
                             if ip_part == '0.0.0.0' and mask_part == '0.0.0.0':
                                 item['trusted_hosts'].append('any')
                             else:
                                 prefix = self._mask_to_prefix(mask_part)
                                 item['trusted_hosts'].append(f"{ip_part}/{prefix}" if prefix is not None else f"{ip_part}/{mask_part}")
                         elif isinstance(val, str) and val != '0.0.0.0 0.0.0.0':
                              # Assume it's already formatted correctly or just an IP
                              item['trusted_hosts'].append(val)
                 if not item['trusted_hosts']: item['trusted_hosts'] = ['any'] # Default if none set

                 # Handle VDOMs (nested block)
                 vdoms_raw = item.get('vdom', [])
                 item['vdoms'] = [v.get('name','?') for v in vdoms_raw if isinstance(v,dict)] if isinstance(vdoms_raw, list) else []

                 target_model.admins[name] = item
            else:
                 print(f"Warning [Handler:system_admin]: System Admin found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_ha(self):
        target_model = self._get_target_model()
        settings = self._read_settings() # Use default iterative version
        target_model.ha = settings if isinstance(settings, dict) else {}

    def _handle_system_ntp(self):
        target_model = self._get_target_model()
        settings = self._read_settings() # Use default iterative version
        target_model.ntp = settings if isinstance(settings, dict) else {}

    def _handle_system_dns(self):
        target_model = self._get_target_model()
        settings = self._read_settings() # Use default iterative version
        target_model.dns = settings if isinstance(settings, dict) else {}

    def _handle_vpn_ssl_settings(self):
        target_model = self._get_target_model() # Typically global
        settings = self._read_settings() # Use default iterative version
        target_model.ssl_settings = settings if isinstance(settings, dict) else {}

    def _handle_vpn_ssl_web_portal(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:ssl_portal]: Expected dict for SSL Portal item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            name = item.get('name')
            if name:
                # bookmarks, etc. are handled as nested blocks by _read_block
                target_model.ssl_portals[name] = item
            else:
                print(f"Warning [Handler:ssl_portal]: SSL Web Portal found without name near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_vpn_ssl_web_policy(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:ssl_policy]: Expected dict for SSL policy item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             item_id = item.get('id', item.get('name')) # Uses name/id? Check config
             if not item_id:
                  print(f"Warning [Handler:ssl_policy]: SSL Policy found without ID/Name near line ~{self.i}. Skipping.", file=sys.stderr)
                  continue
             item['id'] = item_id # Ensure 'id' field exists
             target_model.ssl_policies.append(item)
             
    def _handle_router_vrrp(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:router_vrrp]: Expected dict for VRRP item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             vrid = item.get('id') # Keyed by VRID (which is the 'edit' value)
             if vrid:
                 target_model.vrrp[vrid] = item
             else:
                 print(f"Warning [Handler:router_vrrp]: VRRP group found without VRID near line ~{self.i}. Skipping.", file=sys.stderr)
                 
    def _handle_router_policy(self):
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:router_policy]: Expected dict for PBR item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             item_id = item.get('seq_num', item.get('id')) # Use seq-num if available
             if not item_id:
                  print(f"Warning [Handler:router_policy]: Policy Route found without ID/SeqNum near line ~{self.i}. Skipping.", file=sys.stderr)
                  continue
             item['id'] = item_id # Ensure 'id' field exists
             # Ensure multi-value fields are lists
             multi_keys = ['input_device', 'srcaddr', 'dstaddr', 'protocol', 'service'] 
             for key in multi_keys:
                 current_val = item.get(key)
                 if current_val is not None and not isinstance(current_val, list): item[key] = [current_val]
                 elif current_val is None: item[key] = []
             target_model.policy_routes.append(item)
                 
    # --- Settings Handlers (Single block config) --- 
    def _handle_system_global(self):
        target_model = self._get_target_model() # Usually main model
        settings = self._read_settings() # Use default iterative version
        target_model.system_global = settings if isinstance(settings, dict) else {}
        
    # --- Security Profile Handlers (Common pattern) --- 
    def _handle_profile_block(self, model_key):
         """Generic handler for profile sections (list blocks keyed by name)."""
         target_model = self._get_target_model()
         items = self._read_block() # Use default iterative version
         # Ensure the target attribute exists and is a dictionary
         if not hasattr(target_model, model_key) or not isinstance(getattr(target_model, model_key), dict):
              setattr(target_model, model_key, {})
         profile_dict = getattr(target_model, model_key)
         
         for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:profile_block for {model_key}]: Expected dict for item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             name = item.get('name')
             if name:
                 profile_dict[name] = item
             else:
                  print(f"Warning [Handler:profile_block for {model_key}]: Profile found without name near line ~{self.i}. Skipping.", file=sys.stderr)
         # No need to setattr again unless we created the dict initially
         
    def _handle_antivirus_profile(self): self._handle_profile_block('antivirus')
    def _handle_ips_sensor(self): self._handle_profile_block('ips')
    def _handle_webfilter_profile(self): self._handle_profile_block('web_filter')
    def _handle_application_list(self): self._handle_profile_block('app_control')
    def _handle_dlp_sensor(self): self._handle_profile_block('dlp')
    def _handle_emailfilter_profile(self): self._handle_profile_block('email_filter')
    def _handle_voip_profile(self): self._handle_profile_block('voip')
    def _handle_waf_profile(self): self._handle_profile_block('waf')
    def _handle_ssh_filter_profile(self): self._handle_profile_block('ssl_inspection') 
    def _handle_ssl_ssh_profile(self): self._handle_profile_block('ssl_inspection')
    def _handle_icap_profile(self): self._handle_profile_block('icap')
    def _handle_gtp_profile(self): self._handle_profile_block('gtp')
    def _handle_dnsfilter_profile(self): self._handle_profile_block('system_dns_filter') 
    def _handle_wanopt_profile(self): self._handle_profile_block('wan_opt')
    
    # --- User/Authentication Handlers ---
    def _handle_user_radius(self): self._handle_profile_block('radius_servers')
    def _handle_user_group(self): self._handle_profile_block('user_groups')
    def _handle_user_fortitoken(self): 
         # Uses serial number as edit key ('name' in our parsed dict)
         self._handle_profile_block('fortitoken') 
    def _handle_user_saml(self): self._handle_profile_block('saml')
    def _handle_user_fsso(self): self._handle_profile_block('fsso')

    # --- Schedule Handlers --- 
    def _handle_firewall_schedule_group(self): self._handle_profile_block('schedule_groups')
    def _handle_firewall_schedule_onetime(self): self._handle_profile_block('schedule_onetime')
    def _handle_firewall_schedule_recurring(self): self._handle_profile_block('schedule_recurring')
    
    # --- Other Feature Handlers --- 
    def _handle_firewall_sniffer(self): # Uses ID
        target_model = self._get_target_model()
        items = self._read_block() # Use default iterative version
        if not hasattr(target_model, 'sniffer_profile') or not isinstance(getattr(target_model, 'sniffer_profile'), dict):
             setattr(target_model, 'sniffer_profile', {})
        profile_dict = getattr(target_model, 'sniffer_profile')
        for item in items:
            if not isinstance(item, dict): 
                print(f"Warning [Handler:sniffer]: Expected dict for sniffer item, got {type(item)}. Skipping.", file=sys.stderr)
                continue
            item_id = item.get('id')
            if item_id: profile_dict[item_id] = item
            else: print(f"Warning [Handler:sniffer]: Sniffer profile found without ID near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_fortiguard(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().fortiguard = settings if isinstance(settings, dict) else {}
        
    def _handle_log_syslogd_setting(self): # Example specific log handler
         target_model = self._get_target_model()
         settings = self._read_settings() # Use default iterative version
         if not hasattr(target_model, 'log_settings'): target_model.log_settings = {}
         # Ensure settings is a dict before assigning
         target_model.log_settings['syslogd'] = settings if isinstance(settings, dict) else {} 
         
    def _handle_system_sdwan(self): # Top level SDWAN settings contains nested blocks
         target_model = self._get_target_model()
         settings = self._read_settings() # Use default iterative version
         # Merge settings into the main sd_wan dict
         if not hasattr(target_model, 'sd_wan'): target_model.sd_wan = {}
         # Ensure settings is a dict before updating
         if isinstance(settings, dict): target_model.sd_wan.update(settings)
         else: print(f"Warning [Handler:sdwan]: Expected dict for SDWAN settings, got {type(settings)}. Skipping update.", file=sys.stderr)
         
    def _handle_firewall_ldb_monitor(self): self._handle_profile_block('load_balance') # Store LB monitors by name
    def _handle_wireless_controller_setting(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().wireless_controller = settings if isinstance(settings, dict) else {}
        
    def _handle_switch_controller_global(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().switch_controller = settings if isinstance(settings, dict) else {}
        
    def _handle_system_fortisandbox(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().sandbox = settings if isinstance(settings, dict) else {}
    
    # --- Certificate Handlers --- 
    def _handle_vpn_certificate_local(self): self._handle_cert('local')
    def _handle_vpn_certificate_ca(self): self._handle_cert('ca')
    def _handle_vpn_certificate_remote(self): self._handle_cert('remote')
    def _handle_vpn_certificate_crl(self): self._handle_cert('crl')

    def _handle_cert(self, cert_type):
         target_model = self._get_target_model()
         items = self._read_block() # Use default iterative version
         if not hasattr(target_model, 'certificate'): target_model.certificate = {}
         if cert_type not in target_model.certificate: target_model.certificate[cert_type] = {}
         cert_dict = target_model.certificate[cert_type]
         for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:cert {cert_type}]: Expected dict for cert item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             name = item.get('name')
             if name:
                 # Remove potentially large certificate content for memory? Maybe optional.
                 # item.pop('certificate', None) 
                 cert_dict[name] = item
             else:
                 print(f"Warning [Handler:cert {cert_type}]: Certificate found without name near line ~{self.i}. Skipping.", file=sys.stderr)
         
    # --- Automation/Fabric/Management Handlers ---
    def _handle_system_automation_action(self): self._handle_profile_block('automation') # Store actions by name
    def _handle_system_sdn_connector(self): self._handle_profile_block('sdn_connector')
    def _handle_system_extender_controller_extender(self): self._handle_profile_block('extender')
    def _handle_system_csf(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_csf = settings if isinstance(settings, dict) else {}
    def _handle_system_central_management(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_central_mgmt = settings if isinstance(settings, dict) else {}
    def _handle_system_fm(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_fm = settings if isinstance(settings, dict) else {}
    def _handle_log_fortianalyzer_setting(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_fortianalyzer = settings if isinstance(settings, dict) else {}
    _handle_system_fortianalyzer = _handle_log_fortianalyzer_setting # Alias
    def _handle_log_fortisandbox_setting(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_fortisandbox = settings if isinstance(settings, dict) else {}
    _handle_system_fortisandbox = _handle_log_fortisandbox_setting # Alias

    # --- Legacy/Other VPN Handlers ---
    def _handle_vpn_l2tp(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().vpn_l2tp = settings if isinstance(settings, dict) else {}
    def _handle_vpn_pptp(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().vpn_pptp = settings if isinstance(settings, dict) else {}
    def _handle_vpn_ssl_client(self): 
         print("Warning: Parsing 'config vpn ssl client'. This section is unusual, verify structure.", file=sys.stderr)
         settings = self._read_settings() # Use default iterative version
         self._get_target_model().vpn_ssl_client = settings if isinstance(settings, dict) else {}
         
    # --- System Settings Handlers ---
    def _handle_system_replacemsg_group(self): self._handle_profile_block('system_replacemsg')
    def _handle_system_accprofile(self): self._handle_profile_block('system_accprofile')
    def _handle_system_api_user(self): self._handle_profile_block('system_api_user')
    def _handle_system_sso_admin(self): self._handle_profile_block('system_sso_admin')
    def _handle_system_password_policy(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_password_policy = settings if isinstance(settings, dict) else {}
    def _handle_firewall_interface_policy(self): # Uses ID
         target_model = self._get_target_model()
         items = self._read_block() # Use default iterative version
         if not hasattr(target_model, 'system_interface_policy'): setattr(target_model, 'system_interface_policy', {})
         profile_dict = getattr(target_model, 'system_interface_policy')
         for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:if_policy]: Expected dict for interface policy item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             item_id = item.get('id')
             if item_id: profile_dict[item_id] = item
             else: print(f"Warning [Handler:if_policy]: Interface policy found without ID near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_auto_update(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_auto_update = settings if isinstance(settings, dict) else {}
    def _handle_system_session_ttl(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_session_ttl = settings if isinstance(settings, dict) else {}
    def _handle_system_gre_tunnel(self): self._handle_profile_block('system_gre_tunnel')
    def _handle_system_ddns(self): # Uses ID
         target_model = self._get_target_model()
         items = self._read_block() # Use default iterative version
         if not hasattr(target_model, 'system_ddns'): setattr(target_model, 'system_ddns', {})
         profile_dict = getattr(target_model, 'system_ddns')
         for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:ddns]: Expected dict for DDNS item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             item_id = item.get('id')
             if item_id: profile_dict[item_id] = item
             else: print(f"Warning [Handler:ddns]: DDNS profile found without ID near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_dns_database(self): self._handle_profile_block('system_dns_database')
    def _handle_system_dns_server(self): self._handle_profile_block('system_dns_server')
    def _handle_system_proxy_arp(self): # Uses ID
         target_model = self._get_target_model()
         items = self._read_block() # Use default iterative version
         if not hasattr(target_model, 'system_proxy_arp'): setattr(target_model, 'system_proxy_arp', {})
         profile_dict = getattr(target_model, 'system_proxy_arp')
         for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:proxy_arp]: Expected dict for proxy ARP item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             item_id = item.get('id')
             if item_id: profile_dict[item_id] = item
             else: print(f"Warning [Handler:proxy_arp]: Proxy ARP found without ID near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_virtual_wire_pair(self): self._handle_profile_block('system_virtual_wire_pair')
    def _handle_system_wccp(self): # Uses ID (service-id)
         target_model = self._get_target_model()
         items = self._read_block() # Use default iterative version
         if not hasattr(target_model, 'system_wccp'): setattr(target_model, 'system_wccp', {})
         profile_dict = getattr(target_model, 'system_wccp')
         for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:wccp]: Expected dict for WCCP item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             item_id = item.get('service_id')
             if item_id: profile_dict[item_id] = item
             else: print(f"Warning [Handler:wccp]: WCCP service found without service_id near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_sit_tunnel(self): self._handle_profile_block('system_sit_tunnel')
    def _handle_system_ipip_tunnel(self): self._handle_profile_block('system_ipip_tunnel')
    def _handle_system_vxlan(self): self._handle_profile_block('system_vxlan')
    def _handle_system_geneve(self): self._handle_profile_block('system_geneve')
    def _handle_system_network_visibility(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_network_visibility = settings if isinstance(settings, dict) else {}
    def _handle_system_ptp(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_ptp = settings if isinstance(settings, dict) else {}
    def _handle_system_tos_based_priority(self): # Uses ID
         target_model = self._get_target_model()
         items = self._read_block() # Use default iterative version
         if not hasattr(target_model, 'system_tos_based_priority'): setattr(target_model, 'system_tos_based_priority', {})
         profile_dict = getattr(target_model, 'system_tos_based_priority')
         for item in items:
             if not isinstance(item, dict): 
                 print(f"Warning [Handler:tos_prio]: Expected dict for ToS prio item, got {type(item)}. Skipping.", file=sys.stderr)
                 continue
             item_id = item.get('id')
             if item_id: profile_dict[item_id] = item
             else: print(f"Warning [Handler:tos_prio]: ToS Priority found without ID near line ~{self.i}. Skipping.", file=sys.stderr)

    def _handle_system_email_server(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_email_server = settings if isinstance(settings, dict) else {}
    def _handle_ips_urlfilter_dns(self): 
        settings = self._read_settings() # Use default iterative version
        self._get_target_model().system_ips_urlfilter_dns = settings if isinstance(settings, dict) else {}

    # --- Generic Handler --- 
    def _handle_generic_section(self, raw_section_name, normalized_section_name, block_start_content_index):
        """Handles unrecognized config sections by storing raw data."""
        target_model = self._get_target_model()
        # Set parser position to start of block content
        self.i = block_start_content_index 
        
        # Decide if it's likely a list block or settings block by peeking ahead
        peek_i = self.i # Start peeking from the first content line
        is_list_block = False
        while peek_i < len(self.lines):
            peek_line = self.lines[peek_i].strip()
            if not peek_line or peek_line.startswith('#'):
                peek_i += 1
                continue
            if self.EDIT_RE.match(peek_line):
                is_list_block = True
            break # Found first significant line, decision made
            
        data = None
        try:
            if is_list_block:
                if self.debug: print(f"DEBUG: Generic handler reading '{raw_section_name}' as list block.")
                data = self._read_block() # Use default iterative version
            else:
                if self.debug: print(f"DEBUG: Generic handler reading '{raw_section_name}' as settings block.")
                data = self._read_settings() # Use default iterative version
        except Exception as e:
            print(f"ERROR: Generic handler failed for section '{raw_section_name}' starting near line {block_start_content_index}: {e}", file=sys.stderr)
            # Attempt to recover by skipping the block - reset i first
            self.i = block_start_content_index 
            self._skip_to_next_block_or_end() # Try skipping
            data = f"Error parsing section: {e}" # Store error marker
            
        # Store the data in the model under a generic key
        if not hasattr(target_model, 'generic_configs'): target_model.generic_configs = {}
        # Use normalized name, maybe prefix to avoid clashes?
        storage_key = f"generic_{normalized_section_name}"
        # Store raw name too for reference
        target_model.generic_configs[storage_key] = {
             'raw_name': raw_section_name,
             'data': data
        }
        if self.debug: print(f"Stored generic data for {raw_section_name} under key {storage_key}")

# --- Recovery Helper ---
    def _skip_to_next_block_or_end(self):
        """
        When an error occurs during parsing (e.g., in a handler), this method attempts
        to find the 'end' of the current problematic block or the start of the next
        'config' section. This allows the parser to recover and continue processing
        the rest of the file.

        It assumes self.i currently points to the line *containing* the error or
        the 'config' line of the block where the error occurred.

        Returns:
            bool: True if a potential recovery point ('end' or new 'config') was found,
                  False if recovery failed (e.g., reached EOF).
        """
        recovery_start_line = self.i + 1
        if self.debug: print(f"Recovery: Attempting to skip block starting near line {recovery_start_line}...")

        # Initial nesting level: Assume we are just inside the problematic block's 'config' line.
        # This might be inaccurate if the error happened deep inside, but it's a starting point.
        # A more robust approach might involve tracking depth in the main loop, but adds complexity.
        nesting_level = 1
        self.i += 1 # Move past the assumed problematic 'config' or error line

        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            original_line_index = self.i # For logging

            # Log the line being processed during recovery
            if self.debug: print(f"  RecoverySkip [L{original_line_index + 1}, NestLvl:{nesting_level}]: Processing line: '{line}'")

            # Check for markers that signify the end of the current block or start of a new one

            # 1. Is it a new top-level config section? (Implicit end of current block)
            if self.SECTION_RE.match(line) or \
               self.VDOM_CONFIG_RE.match(line) or \
               self.GLOBAL_CONFIG_RE.match(line):
                if self.debug: print(f"  RecoverySkip: Found new section start at line {original_line_index + 1}. Ending skip.")
                # DO NOT advance self.i here. Let the main loop process this new 'config' line.
                return True

            # 2. Does it look like an 'end' command?
            if self.END_RE.match(line):
                nesting_level -= 1
                if self.debug: print(f"  RecoverySkip: Found 'end' at line {original_line_index + 1}. New nesting level: {nesting_level}")
                if nesting_level == 0:
                    # We likely found the matching 'end' for the block we started skipping.
                    self.i += 1 # Consume the 'end' line
                    if self.debug: print(f"  RecoverySkip: Found matching 'end' at line {original_line_index + 1}. Skip successful.")
                    return True
                elif nesting_level < 0:
                    # We found an 'end' but our nesting count is off (possibly extra 'end' or nested error)
                    # It's safer to stop skipping and let the main loop handle this 'end'.
                    print(f"Warning [Line {original_line_index + 1}]: Recovery skip found 'end' resulting in nesting level {nesting_level}. "
                          f"Stopping skip to let main loop handle potential extra 'end' or parent block end.", file=sys.stderr)
                    # DO NOT advance self.i here. Let the main loop process this potentially problematic 'end'.
                    return True

            # 3. Does it look like the start of a *nested* 'config' section?
            if self.SECTION_RE.match(line): # Re-use SECTION_RE, nested configs look the same
                 nesting_level += 1
                 if self.debug: print(f"  RecoverySkip: Found nested 'config' at line {original_line_index + 1}. New nesting level: {nesting_level}")

            # Advance to the next line if none of the above matched
            self.i += 1

        # If loop finishes, we reached EOF without finding a clear end/next block
        print(f"Warning: Recovery skip reached EOF while searching from line {recovery_start_line}.", file=sys.stderr)
        return False
        
# --- Main Execution --- 
# (Keep main execution block as is)
# ... (rest of the file from main() onwards) ...
