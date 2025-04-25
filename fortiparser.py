#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FortiGate Comprehensive Table Report Parser & Diagram Generator

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
    SECTION_RE = re.compile(r'^config\s+(.+)$') # Removed extra backslash before \s
    # Improved regex for 'edit' command: handles quoted/unquoted names and trailing spaces
    EDIT_RE    = re.compile(r'^edit\s+(?:"([^"]+)"|(\S+))\s*$', re.IGNORECASE)
    SET_RE     = re.compile(r'^set\s+(\S+)\s+(.+)$')
    NEXT_RE    = re.compile(r'^next$')
    END_RE     = re.compile(r'^end$')
    VDOM_CONFIG_RE = re.compile(r'^config\s+vdom$', re.IGNORECASE) # Regex for 'config vdom'
    GLOBAL_CONFIG_RE = re.compile(r'^config\s+global$', re.IGNORECASE) # Regex for 'config global'
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

    def __init__(self, lines):
        self.lines = lines
        self.i     = 0
        self.current_vdom = None # Initialize current VDOM tracking
        self.model = ConfigModel() # Instantiate the model from config_model.py
        self.model.has_vdoms = False # Initialize VDOM flag

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
                 dummy_net = ipaddress.IPv6Network(f"::/{mask_str}", strict=False) 
                 return dummy_net.prefixlen
        except ValueError:
             print(f"Warning: Could not parse mask '{mask_str}' to determine prefix length.", file=sys.stderr)
        return None # Indicate failure

    def parse(self):
        """Parse the config file and return a ConfigModel."""
        self.i = 0
        self.current_vdom = None # Ensure it starts as None
        self.model.has_vdoms = False # Ensure it starts as False

        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                self.i += 1
                continue
                
            # --- VDOM Handling --- 
            if self.VDOM_CONFIG_RE.match(line):
                self._handle_vdom_config() 
                self.current_vdom = None 
                continue
                
            # --- Global Context Handling ---
            if self.GLOBAL_CONFIG_RE.match(line):
                self.current_vdom = 'global' if self.model.has_vdoms else None 
                self.i += 1 # Consume 'config global'
                continue

            # --- Regular Section Parsing (Applies to Root, Global, or after VDOM block) --- 
            m = self.SECTION_RE.match(line)
            if m:
                raw_section_name = m.group(1).strip()
                normalized_section_name = raw_section_name.lower().replace(' ', '_').replace('-', '_')
                
                handler_method_name = self.SECTION_ALIASES.get(normalized_section_name)
                
                if not handler_method_name:
                    handler_method_name = f'_handle_{normalized_section_name}'
                
                handler = getattr(self, handler_method_name, None)

                if handler:
                    try:
                        handler()
                    except Exception as e:
                        print(f"ERROR: Handler {handler_method_name} failed for section '{raw_section_name}' at line {self.i+1}: {e}", file=sys.stderr)
                        self._skip_block()
                else:
                    self._handle_generic_section(raw_section_name, normalized_section_name)
                continue
            
            # If not a section start or handled line, just advance
            self.i += 1

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
        """Skip lines until the matching 'end' is found."""
        nesting_level = 1
        self.i += 1
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            if line.startswith('config '):
                nesting_level += 1
            elif self.END_RE.match(line):
                nesting_level -= 1
                if nesting_level == 0:
                    self.i += 1
                    return
            self.i += 1
        print("Warning: Reached end of file while skipping block.", file=sys.stderr)

    def _read_block(self):
        """Read a block of settings for a list-based config section (e.g., firewall policy)."""
        items = []
        self.i += 1
        current_item = None
        nesting_level = 1
        
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            current_item_id = current_item.get('id', current_item.get('name', 'None')) if current_item else 'None'

            if line.startswith('config '):
                 nesting_level += 1
                 nested_section_name = line.split(None, 1)[1].strip()
                 nested_key = nested_section_name.lower().replace(' ','_').replace('-','_')
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
                     
                 if is_list_block:
                     nested_data = self._read_block()
                 else:
                     nested_data = self._read_settings()
                 
                 nesting_level -= 1

                 if current_item is not None:
                     current_item[nested_key] = nested_data
                 else:
                      pass
                 if self.i < len(self.lines):
                      pass
                 else:
                      break
                 continue

            m_edit = self.EDIT_RE.match(line)
            m_set = self.SET_RE.match(line)
            m_next = self.NEXT_RE.match(line)
            m_end = self.END_RE.match(line)
            
            if m_edit:
                if current_item is not None:
                    items.append(current_item)
                edit_val = m_edit.group(1) or m_edit.group(2)
                id_key = 'id' if edit_val.isdigit() else 'name'
                current_item = {id_key: edit_val}
            elif m_set and current_item is not None:
                key = m_set.group(1).replace('-', '_')
                val = m_set.group(2).strip()
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                if ' ' in val and not (val.startswith('"') and val.endswith('"')):
                    split_vals = []
                    current_val = ''
                    in_quotes = False
                    for char in val:
                        if char == '"' :
                            in_quotes = not in_quotes
                        elif char == ' ' and not in_quotes:
                            if current_val:
                                split_vals.append(current_val)
                            current_val = ''
                        else:
                            current_val += char
                    if current_val:
                        split_vals.append(current_val)
                    
                    # --- FIX: Handle 'set ip|subnet <ip> <mask>' & Convert to CIDR ---    
                    if key in ['ip', 'subnet'] and len(split_vals) == 2:
                        ip_part = split_vals[0]
                        mask_part = split_vals[1]
                        prefix = self._mask_to_prefix(mask_part)
                        if prefix is not None:
                             current_item[key] = f"{ip_part}/{prefix}" # Store as ip/prefix string
                        else:
                             # Store as ip/mask if prefix conversion failed
                             current_item[key] = f"{ip_part}/{mask_part}"
                             print(f"Warning: Storing '{key}' as ip/mask for item '{current_item.get('name', current_item.get('id', '?'))}' due to mask parse failure.", file=sys.stderr)
                    elif len(split_vals) > 1:
                        current_item[key] = split_vals # Store other multi-word values as list
                    else:
                        current_item[key] = split_vals[0] if split_vals else '' 
                    # --- FIX END ---
                else:
                    current_item[key] = val
            elif m_next:
                 if current_item is not None:
                     items.append(current_item)
                 current_item = None
            elif m_end:
                 nesting_level -= 1
                 if nesting_level == 0:
                     if current_item is not None:
                         items.append(current_item)
                     self.i += 1
                     return items
                 else:
                     pass
            elif not line or line.startswith('#'):
                 pass

            self.i += 1
            
        print(f"Warning: Reached end of file while reading block.", file=sys.stderr)
        if current_item is not None:
            items.append(current_item)
        return items

    def _read_settings(self):
        """Read a block of settings for a single-item config section (e.g., system dns)."""
        settings = {}
        self.i += 1
        nesting_level = 1
        
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            
            if line.startswith('config '):
                 nesting_level += 1
                 nested_section_name = line.split(None, 1)[1].strip()
                 nested_key = nested_section_name.lower().replace(' ','_').replace('-','_')
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
                 
                 if is_list_block:
                      nested_data = self._read_block()
                 else:
                      nested_data = self._read_settings()
                 
                 nesting_level -= 1

                 settings[nested_key] = nested_data

                 if self.i < len(self.lines):
                      pass
                 else:
                      break
                 continue

            m_set = self.SET_RE.match(line)
            m_end = self.END_RE.match(line)
            
            if m_set:
                key = m_set.group(1).replace('-', '_')
                val = m_set.group(2).strip()
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                if ' ' in val and not (val.startswith('"') and val.endswith('"')):
                    split_vals = []
                    current_val = ''
                    in_quotes = False
                    for char in val:
                        if char == '"' :
                            in_quotes = not in_quotes
                        elif char == ' ' and not in_quotes:
                            if current_val:
                                split_vals.append(current_val)
                            current_val = ''
                        else:
                            current_val += char
                    if current_val:
                        split_vals.append(current_val)
                        
                    # --- FIX: Handle 'set ip|subnet <ip> <mask>' & Convert to CIDR ---    
                    if key in ['ip', 'subnet'] and len(split_vals) == 2:
                        ip_part = split_vals[0]
                        mask_part = split_vals[1]
                        prefix = self._mask_to_prefix(mask_part)
                        if prefix is not None:
                             settings[key] = f"{ip_part}/{prefix}" # Store as ip/prefix string
                        else:
                             # Store as ip/mask if prefix conversion failed
                             settings[key] = f"{ip_part}/{mask_part}"
                             print(f"Warning: Storing '{key}' as ip/mask in settings block due to mask parse failure.", file=sys.stderr)
                    elif len(split_vals) > 1:
                        settings[key] = split_vals # Store other multi-word values as list
                    else:
                        settings[key] = split_vals[0] if split_vals else '' 
                    # --- FIX END ---
                else:
                     settings[key] = val
            elif m_end:
                 nesting_level -= 1
                 if nesting_level == 0:
                     self.i += 1
                     return settings
                 else:
                     pass
            elif not line or line.startswith('#'):
                 pass

            self.i += 1
            
        print("Warning: Reached end of file while reading settings.", file=sys.stderr)
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
        settings = self._read_settings()
        target_model.bgp = settings

    # BGP sub-sections handled implicitly by _read_settings recursion
    # def _handle_router_bgp_neighbor(self):
    #      return self._read_block()
    # def _handle_router_bgp_network(self):
    #      return self._read_block()
    # def _handle_router_bgp_redistribute(self, section_name):
    #     # Handler for blocks like 'config redistribute connected'
    #     # Needs to store based on the type (connected, ospf, etc.)
    #     # The section name 'redistribute connected' needs parsing
    #     redist_type = section_name.split('_')[-1] # Get 'connected'
    #     settings = self._read_settings()
    #     # Return tuple or dict indicating type? _read_settings needs modification
    #     # For now, assume _read_settings returns dict, store it under type
    #     return {redist_type: settings} # This structure might need adjustment in _read_settings

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
    parser = FortiParser(config_lines)
    try:
        model = parser.parse()
        print("Parsing complete.")
    except Exception as e:
        print(f"\n!!! Critical parsing error encountered: {e}", file=sys.stderr)
        print("Attempting to proceed, but results may be incomplete.", file=sys.stderr)
        # Use the partially populated model from the parser instance
        model = parser.model 
        # Consider exiting here depending on severity
        # sys.exit(1)
        
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
                  # Potentially print stack trace here for debugging
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
