#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilities for comparing two parsed FortiGate configuration models (ConfigModel).
"""

from config_model import ConfigModel
import pprint

def compare_objects(obj1, obj2, ignore_keys=None):
    """Compares two dictionary objects, returning changes.

    Args:
        obj1: The first dictionary object.
        obj2: The second dictionary object.
        ignore_keys: A set of keys to ignore during comparison.

    Returns:
        A dictionary describing the changes:
        {'field': {'old': value1, 'new': value2}, ...}
        Returns None if objects are identical (considering ignore_keys).
    """
    if ignore_keys is None:
        ignore_keys = set()

    diff = {}
    all_keys = set(obj1.keys()) | set(obj2.keys())

    for key in all_keys:
        if key in ignore_keys:
            continue

        val1 = obj1.get(key)
        val2 = obj2.get(key)

        # Normalize potentially list-based values that should be strings for comparison consistency
        # Example: 'member' fields which might be parsed as list or string
        if isinstance(val1, list) and len(val1) == 1: val1 = val1[0]
        if isinstance(val2, list) and len(val2) == 1: val2 = val2[0]

        # Simple comparison for now, can be enhanced for nested structures/lists
        if val1 != val2:
            diff[key] = {'old': val1, 'new': val2}

    return diff if diff else None

def compare_config_section(section1, section2, section_name, id_key='name'):
    """Compares a specific section between two models.

    Handles both dictionary-based sections (like interfaces, addresses)
    and list-based sections (like policies, routes).

    Args:
        section1: The section data from the first model (dict or list).
        section2: The section data from the second model (dict or list).
        section_name: The name of the section being compared (for reporting).
        id_key: The key used to identify unique items within the section
                ('name' for dicts like interfaces, 'id' or 'name' for lists like policies).

    Returns:
        A dictionary containing 'added', 'deleted', and 'modified' items.
    """
    results = {'added': [], 'deleted': [], 'modified': {}}

    if isinstance(section1, dict) and isinstance(section2, dict):
        keys1 = set(section1.keys())
        keys2 = set(section2.keys())

        added_keys = keys2 - keys1
        deleted_keys = keys1 - keys2
        common_keys = keys1 & keys2

        for key in added_keys:
            # results['added'].append({id_key: key, **section2[key]}) # Store the added object - Error prone if value is not dict
            # FIX: Store value under a specific key instead of unpacking
            results['added'].append({id_key: key, 'value': section2[key]})

        for key in deleted_keys:
            # results['deleted'].append({id_key: key, **section1[key]}) # Store the deleted object - Error prone if value is not dict
            # FIX: Store value under a specific key instead of unpacking
            results['deleted'].append({id_key: key, 'value': section1[key]})

        for key in common_keys:
            # Check if both values are dicts before calling compare_objects
            val1 = section1[key]
            val2 = section2[key]
            if isinstance(val1, dict) and isinstance(val2, dict):
                diff = compare_objects(val1, val2)
                if diff:
                    results['modified'][key] = diff
            elif val1 != val2: # Simple comparison if not both are dicts (e.g., for addr_groups lists)
                results['modified'][key] = {'value': {'old': val1, 'new': val2}}

    elif isinstance(section1, list) and isinstance(section2, list):
        # Use id_key to match items in the list
        map1 = {item.get(id_key): item for item in section1 if item.get(id_key) is not None}
        map2 = {item.get(id_key): item for item in section2 if item.get(id_key) is not None}

        keys1 = set(map1.keys())
        keys2 = set(map2.keys())

        added_keys = keys2 - keys1
        deleted_keys = keys1 - keys2
        common_keys = keys1 & keys2

        for key in added_keys:
            results['added'].append(map2[key])

        for key in deleted_keys:
            results['deleted'].append(map1[key])

        for key in common_keys:
            # Use a unique identifier from the object itself if possible
            identifier = map1[key].get(id_key, f"item_{key}") # Fallback if key isn't in object
            diff = compare_objects(map1[key], map2[key])
            if diff:
                results['modified'][identifier] = diff # Use unique ID/name as key

        # Handle items without a usable ID key (less common, compare sequentially?)
        # For now, we only compare items with IDs.

    else:
        # Handle type mismatch or unsupported types
        print(f"Warning: Type mismatch or unsupported type for section '{section_name}'. Cannot compare.")
        # Store raw difference if types differ significantly
        if type(section1) != type(section2) or section1 != section2:
             results['modified']['SECTION_TYPE_MISMATCH'] = {'old': str(type(section1)), 'new': str(type(section2))}


    # Only return the section if there are actual changes
    if results['added'] or results['deleted'] or results['modified']:
        return results
    else:
        return None


def compare_models(model1: ConfigModel, model2: ConfigModel):
    """Compares two ConfigModel instances and returns a dictionary of differences.

    Args:
        model1: The first ConfigModel instance (e.g., 'old').
        model2: The second ConfigModel instance (e.g., 'new').

    Returns:
        A dictionary where keys are section names and values describe
        the differences found ('added', 'deleted', 'modified').
    """
    diff_results = {}

    # --- Define sections and their primary identifier keys ---
    # Format: { 'attribute_name_in_model': ('Display Name', 'id_key') }
    sections_to_compare = {
        'interfaces':       ('System Interfaces', 'name'),
        'zones':            ('Firewall Zones', 'name'),
        'routes':           ('Static Routes', 'name'), # Uses 'name' derived from seq-num in parser
        'policies':         ('Firewall Policies', 'id'),
        'addresses':        ('Address Objects', 'name'),
        'addr_groups':      ('Address Groups', 'name'),
        'services':         ('Custom Services', 'name'),
        'svc_groups':       ('Service Groups', 'name'),
        'vips':             ('Virtual IPs (VIPs)', 'name'),
        'vip_groups':       ('VIP Groups', 'name'),
        'ippools':          ('IP Pools', 'name'),
        'dhcp_servers':     ('DHCP Servers', 'id'),
        'admins':           ('Administrators', 'name'),
        'phase1':           ('VPN Phase 1', 'name'),
        'phase2':           ('VPN Phase 2', 'name'),
        # System settings (often single dicts, compare as one modified item)
        'dns':              ('System DNS', None), # Treat as single settings block
        'ntp':              ('System NTP', None),
        'ha':               ('System HA', None),
        'system_global':    ('System Global', None),
        'fortiguard':       ('System FortiGuard', None),
        # Security Profiles
        'antivirus':        ('Antivirus Profiles', 'name'),
        'ips':              ('IPS Sensors', 'name'),
        'web_filter':       ('Web Filter Profiles', 'name'),
        'app_control':      ('Application Control Profiles', 'name'),
        'ssl_inspection':   ('SSL Inspection Profiles', 'name'),
        # Add other sections as needed...
        'radius_servers':   ('RADIUS Servers', 'name'),
        'ldap_servers':     ('LDAP Servers', 'name'),
        'policy_routes':    ('Policy Routes', 'id'),
    }

    for attr_name, (display_name, id_key) in sections_to_compare.items():
        section1 = getattr(model1, attr_name, None)
        section2 = getattr(model2, attr_name, None)

        # Handle cases where a section might not exist in one model (e.g., due to parse errors or version diffs)
        if section1 is None and section2 is None:
            continue # Skip if section doesn't exist in either model
        elif section1 is None:
            # Entire section added
            diff_results[display_name] = {'added': list(section2.values()) if isinstance(section2, dict) else section2, 'deleted': [], 'modified': {}}
            continue
        elif section2 is None:
            # Entire section deleted
            diff_results[display_name] = {'deleted': list(section1.values()) if isinstance(section1, dict) else section1, 'added': [], 'modified': {}}
            continue

        # Special handling for single setting dictionaries
        if id_key is None:
            if isinstance(section1, dict) and isinstance(section2, dict):
                diff = compare_objects(section1, section2)
                if diff:
                    diff_results[display_name] = {'added': [], 'deleted': [], 'modified': {'Settings': diff}}
            elif section1 != section2: # If not dicts, basic comparison
                 diff_results[display_name] = {'added': [], 'deleted': [], 'modified': {'Value': {'old': section1, 'new': section2}}}
        else:
            section_diff = compare_config_section(section1, section2, display_name, id_key)
            if section_diff:
                diff_results[display_name] = section_diff

    # TODO: Compare VDOMs if present model1.has_vdoms or model2.has_vdoms

    return diff_results

def format_value(value):
    """Formats a value for display in the diff output."""
    if isinstance(value, list):
        # Pretty print lists for better readability if they contain dicts
        if value and all(isinstance(item, dict) for item in value):
            return '\n' + pprint.pformat(value, indent=2, width=60)
        return ', '.join(map(str, value))
    if isinstance(value, dict):
         # Pretty print dicts
         return '\n' + pprint.pformat(value, indent=2, width=60)
    if value is None:
        return '_(Not Set)_'
    return str(value)

def format_diff_results(diff_data: dict):
    """Formats the structured diff data into HTML for Streamlit display."""
    html_output = []
    # Basic CSS for table styling - MODIFIED FOR BETTER CONTRAST
    html_output.append("""
    <style>
        .diff-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        .diff-table th, .diff-table td {
            border: 1px solid #cccccc;
            padding: 8px;
            text-align: left;
            vertical-align: top;
            color: #333333; /* Default darker text color */
        }
        .diff-table th {
            background-color: #e0e0e0;
        }
        /* Ensure text color is dark for added/deleted rows */
        .diff-table tr.added td {
            background-color: #e6ffed; /* Slightly adjusted green */
            color: #222222; /* Ensure dark text */
        }
        .diff-table tr.deleted td {
             background-color: #ffebee; /* Slightly adjusted red/pink */
             color: #222222; /* Ensure dark text */
        }
        .diff-table tr.modified td:first-child { font-weight: bold; }
        /* Ensure code/pre blocks within diffs also have good contrast */
        .diff-table pre, .diff-table code {
             background-color: #f8f8f8;
             padding: 5px;
             border: 1px solid #ddd;
             white-space: pre-wrap;
             word-wrap: break-word;
             color: #333333; /* Ensure code text is dark */
        }
        .change-detail { margin-left: 15px; }
        .field-name { font-weight: bold; }
    </style>
    """)

    has_changes = False
    for section_name, changes in diff_data.items():
        if not (changes.get('added') or changes.get('deleted') or changes.get('modified')):
            continue

        has_changes = True
        section_html = [f"<h3>{section_name}</h3>"]
        section_html.append("<table class='diff-table'>")
        section_html.append("<thead><tr><th>Item</th><th>Change Type</th><th>Details</th></tr></thead>")
        section_html.append("<tbody>")

        # --- Modified Items ---
        if changes.get('modified'):
            for item_id, modifications in sorted(changes['modified'].items()):
                details_html = ["<ul>"] # Start list for modifications
                for field, change in sorted(modifications.items()):
                    old_val_str = format_value(change.get('old'))
                    new_val_str = format_value(change.get('new'))
                    # Use <pre> for multi-line content
                    old_formatted = f"<pre>{old_val_str}</pre>" if '\n' in old_val_str else f"<code>{old_val_str}</code>"
                    new_formatted = f"<pre>{new_val_str}</pre>" if '\n' in new_val_str else f"<code>{new_val_str}</code>"

                    details_html.append(f"<li><span class='field-name'>{field}:</span> {old_formatted} &rarr; {new_formatted}</li>")
                details_html.append("</ul>")
                section_html.append(f"<tr class='modified'><td>{item_id}</td><td>Modified</td><td>{''.join(details_html)}</td></tr>")

        # --- Added Items ---
        if changes.get('added'):
            for item in sorted(changes['added'], key=lambda x: str(x.get('name', x.get('id', 'zzzzz')))):
                 item_id_key = next((k for k in ['name', 'id', 'seq_num'] if k in item), None)
                 item_id_val = item.get(item_id_key, 'Unknown Item')
                 item_details = format_value(item) # Use pformat for the whole object
                 section_html.append(f"<tr class='added'><td>{item_id_val}</td><td>Added</td><td><pre>{item_details}</pre></td></tr>")

        # --- Deleted Items ---
        if changes.get('deleted'):
             for item in sorted(changes['deleted'], key=lambda x: str(x.get('name', x.get('id', 'zzzzz')))):
                 item_id_key = next((k for k in ['name', 'id', 'seq_num'] if k in item), None)
                 item_id_val = item.get(item_id_key, 'Unknown Item')
                 item_details = format_value(item)
                 section_html.append(f"<tr class='deleted'><td>{item_id_val}</td><td>Deleted</td><td><pre>{item_details}</pre></td></tr>")

        section_html.append("</tbody></table>")
        html_output.extend(section_html)

    if not has_changes:
        return "<p><strong>No structural differences found between the configurations.</strong></p>"

    return '\n'.join(html_output)

# Example Usage (for testing):
if __name__ == '__main__':
    # Create dummy models for testing
    model_a = ConfigModel()
    model_a.interfaces['port1'] = {'name': 'port1', 'ip': '192.168.1.1/24', 'status': 'up', 'description': 'LAN'}
    model_a.interfaces['port2'] = {'name': 'port2', 'ip': '10.0.0.1/24', 'status': 'down'}
    model_a.policies.append({'id': '1', 'srcintf': ['port1'], 'dstintf': ['port2'], 'action': 'accept'})
    model_a.dns = {'primary': '8.8.8.8', 'secondary': '1.1.1.1'}


    model_b = ConfigModel()
    model_b.interfaces['port1'] = {'name': 'port1', 'ip': '192.168.1.254/24', 'status': 'up', 'description': 'Main LAN'} # Changed IP and description
    # port2 deleted
    model_b.interfaces['port3'] = {'name': 'port3', 'ip': '172.16.0.1/24', 'status': 'up'} # Added port3
    model_b.policies.append({'id': '1', 'srcintf': ['port1'], 'dstintf': ['port3'], 'action': 'accept', 'logtraffic': 'enable'}) # Changed dstintf, added logtraffic
    model_b.policies.append({'id': '2', 'srcintf': ['port3'], 'dstintf': ['port1'], 'action': 'deny'}) # Added policy 2
    model_b.dns = {'primary': '8.8.8.8', 'secondary': '1.0.0.1'} # Changed secondary DNS


    print("--- Comparing Models --- A -> B")
    diff = compare_models(model_a, model_b)
    pprint.pprint(diff)

    print("\n--- Formatted Diff --- A -> B")
    formatted = format_diff_results(diff)
    print(formatted)

    print("\n--- Comparing Models --- B -> A")
    diff_rev = compare_models(model_b, model_a)
    # pprint.pprint(diff_rev)
    print("\n--- Formatted Diff --- B -> A")
    formatted_rev = format_diff_results(diff_rev)
    print(formatted_rev) 
