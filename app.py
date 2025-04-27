import streamlit as st
import io
import os
import sys
import traceback # Import traceback for better error handling
import subprocess # For checking Graphviz
import difflib # For basic text diffing (can be enhanced)
# --- Add imports for PDF generation ---
from io import BytesIO
from xhtml2pdf import pisa

# Add the project root to the Python path to allow importing modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import your existing classes - ensure these files are in the same directory or path is correct
try:
    from fortiparser import FortiParser
    from config_model import ConfigModel
    from diagram_generator import NetworkDiagramGenerator, ConfigAuditor
    from utils import print_table, get_table_dataframe # We might need to adapt this later
    # Import the new diff utility (we will create this file next)
    from diff_utils import compare_models, format_diff_results # NOW IMPORTING!
except ImportError as e:
    st.error(f"Error importing modules: {e}")
    st.error("Please ensure fortiparser.py, config_model.py, diagram_generator.py, utils.py, and diff_utils.py are in the correct path.")
    st.stop() # Stop execution if imports fail

# --- Page Configuration (Optional but Recommended) ---
st.set_page_config(
    page_title="FortiParser Web UI",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Initialise Session State ---
if 'model1' not in st.session_state:
    st.session_state.model1 = None
if 'model2' not in st.session_state:
    st.session_state.model2 = None
if 'uploaded_file_name_1' not in st.session_state:
    st.session_state.uploaded_file_name_1 = None
if 'uploaded_file_name_2' not in st.session_state:
    st.session_state.uploaded_file_name_2 = None
if 'analysis_done' not in st.session_state:
    st.session_state.analysis_done = False
if 'comparison_done' not in st.session_state:
    st.session_state.comparison_done = False
if 'trace_done' not in st.session_state:
    st.session_state.trace_done = False
if 'diff_results' not in st.session_state:
    st.session_state.diff_results = None
if 'diff_formatted' not in st.session_state:
    st.session_state.diff_formatted = None
if 'audit_findings' not in st.session_state:
    st.session_state.audit_findings = None
if 'diagram_file_path' not in st.session_state:
    st.session_state.diagram_file_path = None
if 'legend_file_path' not in st.session_state:
    st.session_state.legend_file_path = None
if 'unused_report_data' not in st.session_state:
    st.session_state.unused_report_data = None
if 'summary_data' not in st.session_state:
    st.session_state.summary_data = None
if 'connectivity_tree' not in st.session_state:
    st.session_state.connectivity_tree = None
if 'trace_result' not in st.session_state:
    st.session_state.trace_result = None
if 'trace_status_msg' not in st.session_state:
    st.session_state.trace_status_msg = None
if 'processing_error' not in st.session_state:
    st.session_state.processing_error = False
# --- Add key for saved analysis profiles ---
if 'saved_profiles' not in st.session_state:
    st.session_state.saved_profiles = {}


# --- Main Application Logic ---
st.title("🔥 FortiParser Web UI")
st.write("Upload your FortiGate configuration file and explore the options.")

# --- Sidebar for Options ---
st.sidebar.header("Configuration Options")
uploaded_file = st.sidebar.file_uploader("Choose a FortiGate config file (.conf)", type=['conf', 'txt'])
output_basename = st.sidebar.text_input("Output File Basename", value="network_topology")

# --- Logic to handle file uploads and reset state ---
if uploaded_file is not None:
    # Check if it's a new file compared to the one stored in session state
    if uploaded_file.name != st.session_state.uploaded_file_name_1:
        st.session_state.uploaded_file_name_1 = uploaded_file.name
        st.session_state.model1 = None # Clear the previous model
        st.session_state.analysis_done = False # Reset analysis flag
        st.session_state.trace_done = False    # Reset trace flag
        st.session_state.processing_error = False # Reset error flag
        # Clear previous results to avoid showing stale data
        st.session_state.audit_findings = None
        st.session_state.diagram_file_path = None
        st.session_state.legend_file_path = None
        st.session_state.unused_report_data = None
        st.session_state.summary_data = None
        st.session_state.connectivity_tree = None
        st.session_state.trace_result = None
        st.session_state.trace_status_msg = None
        st.info(f"New file '{uploaded_file.name}' loaded. Ready for analysis.") # Inform user
    # Add explicit check here to prevent AttributeError if uploaded_file becomes None unexpectedly
    elif uploaded_file is not None and uploaded_file.name == st.session_state.uploaded_file_name_1 and not st.session_state.model1:
        # If the same file is re-uploaded but the model is somehow None, reset flags
        st.session_state.analysis_done = False
        st.session_state.trace_done = False
        st.session_state.processing_error = False

st.sidebar.markdown("---") # Separator

# --- Trace Options ---
st.sidebar.subheader("Path Trace (Optional)")
trace_src = st.sidebar.text_input("Source IP")
trace_dst = st.sidebar.text_input("Destination IP")
trace_port = st.sidebar.text_input("Destination Port/Service")
trace_proto = st.sidebar.selectbox("Protocol", ["tcp", "udp", "icmp"], index=0)
run_trace = st.sidebar.checkbox("Enable Path Trace", help="If enabled, only tracing will be performed.")

st.sidebar.markdown("---") # Separator

# --- Diff Feature ---
st.sidebar.subheader("Compare Configurations (Optional)")
uploaded_file_compare = st.sidebar.file_uploader("Choose a SECOND config file to compare", type=['conf', 'txt'], key="compare_file")
run_compare = st.sidebar.button("Compare Configurations", disabled=(uploaded_file is None or uploaded_file_compare is None), help="Compare the two uploaded configuration files.")

# --- Logic to handle second file upload for comparison ---
if uploaded_file_compare is not None:
    if uploaded_file_compare.name != st.session_state.uploaded_file_name_2:
        st.session_state.uploaded_file_name_2 = uploaded_file_compare.name
        st.session_state.model2 = None # Clear previous model 2
        st.session_state.comparison_done = False # Reset comparison flag
        st.session_state.diff_results = None
        st.session_state.diff_formatted = None
        st.info(f"Second file '{uploaded_file_compare.name}' loaded for comparison.")
    # Add explicit check here as well
    elif uploaded_file_compare is not None and uploaded_file_compare.name == st.session_state.uploaded_file_name_2 and not st.session_state.model2:
        st.session_state.comparison_done = False

st.sidebar.markdown("---") # Separator

# --- Generation Options ---
st.sidebar.subheader("Generation Options")
run_analysis = st.sidebar.button("Parse & Analyse Configuration", disabled=(uploaded_file is None))
# skip_diagram = st.sidebar.checkbox("Skip Diagram Generation", value=False, disabled=run_trace)
# skip_tables = st.sidebar.checkbox("Skip Console Table Generation", value=False, disabled=run_trace) # We'll use web tables instead

# --- Analysis Profile Management (Save/Load/Delete) ---
st.sidebar.markdown("---")
st.sidebar.subheader("Analysis Profiles (Session Only)")

# Get saved profile names for the selectbox
saved_profile_names = list(st.session_state.saved_profiles.keys())

# Disable widgets if no analysis is done or no profiles are saved
can_save = st.session_state.get('analysis_done', False) and not st.session_state.get('processing_error', True)
can_load_delete = bool(saved_profile_names)

profile_name_to_save = st.sidebar.text_input(
    "Profile Name to Save",
    value="",
    help="Enter a name to save the current analysis results.",
    disabled=not can_save
)

# SAVE BUTTON
if st.sidebar.button("💾 Save Current Analysis", disabled=not can_save or not profile_name_to_save):
    # Create a dictionary to hold the current analysis state
    # Note: Storing the model itself might consume memory. Consider saving derived data if models get very large.
    profile_data = {
        'model1': st.session_state.get('model1'),
        'uploaded_file_name_1': st.session_state.get('uploaded_file_name_1'),
        'audit_findings': st.session_state.get('audit_findings'),
        'diagram_file_path': st.session_state.get('diagram_file_path'),
        'legend_file_path': st.session_state.get('legend_file_path'),
        'unused_report_data': st.session_state.get('unused_report_data'),
        'summary_data': st.session_state.get('summary_data'),
        'connectivity_tree': st.session_state.get('connectivity_tree'),
        'analysis_done': True, # Mark as analysed
        'output_basename': output_basename # Save the basename used for generation
    }
    # Store it in the saved_profiles dict
    st.session_state.saved_profiles[profile_name_to_save] = profile_data
    st.sidebar.success(f"Analysis saved as profile: '{profile_name_to_save}'")
    # Trigger a rerun to update the selectbox immediately
    st.rerun()

# --- Load / Delete Section ---
if can_load_delete:
    profile_to_manage = st.sidebar.selectbox(
        "Manage Saved Profiles",
        options=saved_profile_names,
        index=0,
        help="Select a saved analysis profile to load or delete."
    )

    col1, col2 = st.sidebar.columns(2)

    # LOAD BUTTON
    with col1:
        if st.button("📂 Load Analysis", disabled=not profile_to_manage):
            # Retrieve the saved data
            loaded_data = st.session_state.saved_profiles.get(profile_to_manage)
            if loaded_data:
                # Overwrite current session state with loaded data
                st.session_state.model1 = loaded_data.get('model1')
                st.session_state.uploaded_file_name_1 = loaded_data.get('uploaded_file_name_1')
                st.session_state.audit_findings = loaded_data.get('audit_findings')
                st.session_state.diagram_file_path = loaded_data.get('diagram_file_path')
                st.session_state.legend_file_path = loaded_data.get('legend_file_path')
                st.session_state.unused_report_data = loaded_data.get('unused_report_data')
                st.session_state.summary_data = loaded_data.get('summary_data')
                st.session_state.connectivity_tree = loaded_data.get('connectivity_tree')
                st.session_state.analysis_done = loaded_data.get('analysis_done', True)
                # Maybe update output_basename? Or keep the current one? Let's keep current for now.
                # output_basename = loaded_data.get('output_basename', "network_topology")

                # Reset other potentially conflicting states
                st.session_state.trace_done = False
                st.session_state.comparison_done = False
                st.session_state.processing_error = False
                st.session_state.model2 = None
                st.session_state.uploaded_file_name_2 = None
                st.session_state.diff_results = None
                st.session_state.diff_formatted = None
                st.session_state.trace_result = None
                st.session_state.trace_status_msg = None

                st.success(f"Loaded analysis profile: '{profile_to_manage}'")
                # Rerun to update the main page content
                st.rerun()
            else:
                st.error(f"Could not find saved data for profile: '{profile_to_manage}'")

    # DELETE BUTTON
    with col2:
        if st.button("🗑️ Delete", disabled=not profile_to_manage, help="Delete the selected profile (cannot be undone)."):
            if profile_to_manage in st.session_state.saved_profiles:
                del st.session_state.saved_profiles[profile_to_manage]
                st.sidebar.success(f"Deleted profile: '{profile_to_manage}'")
                # Rerun to update the selectbox
                st.rerun()
            else:
                st.sidebar.error(f"Profile '{profile_to_manage}' not found for deletion.")
else:
    st.sidebar.caption("(No analysis profiles saved in this session)")

# --- Export Report ---
st.sidebar.markdown("---")
st.sidebar.subheader("Export Full Report")

# Add format selection
export_format = st.sidebar.radio(
    "Select Export Format",
    ('HTML', 'PDF'),
    index=0, # Default to HTML
    horizontal=True
)

# Button is enabled only if analysis is done and there was no processing error
can_export = st.session_state.get('analysis_done', False) and not st.session_state.get('processing_error', True)

if st.sidebar.button(f"📄 Generate {export_format} Report", disabled=not can_export):
    if st.session_state.get('model1') and st.session_state.get('uploaded_file_name_1'):
        model = st.session_state.model1
        file_name = st.session_state.uploaded_file_name_1
        report_html = []

        # --- Basic HTML Structure and CSS --- 
        report_html.append("<!DOCTYPE html>")
        report_html.append("<html lang='en'>")
        report_html.append("<head>")
        report_html.append("    <meta charset='UTF-8'>")
        report_html.append(f"    <title>FortiGate Analysis Report: {file_name}</title>")
        report_html.append("    <style>")
        report_html.append("        body { font-family: sans-serif; margin: 20px; }")
        report_html.append("        h1, h2, h3 { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 30px; }")
        report_html.append("        h1 { font-size: 1.8em; }")
        report_html.append("        h2 { font-size: 1.5em; }")
        report_html.append("        h3 { font-size: 1.2em; margin-top: 20px; border-bottom: none; }")
        report_html.append("        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }")
        report_html.append("        th, td { border: 1px solid #cccccc; padding: 8px; text-align: left; vertical-align: top; font-size: 0.9em; }")
        report_html.append("        th { background-color: #e0e0e0; font-weight: bold; }")
        report_html.append("        pre { background-color: #f8f8f8; padding: 10px; border: 1px solid #ddd; white-space: pre-wrap; word-wrap: break-word; }")
        report_html.append("        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }")
        report_html.append("        .summary-item { background-color: #f0f0f0; padding: 10px; border-radius: 5px; text-align: center; }")
        report_html.append("        .summary-item .label { font-weight: bold; display: block; margin-bottom: 5px; font-size: 0.9em; }")
        report_html.append("        .summary-item .value { font-size: 1.1em; }")
        report_html.append("        .audit-Critical { border-left: 5px solid #dc3545; padding-left: 10px; background-color: #f8d7da; }")
        report_html.append("        .audit-High { border-left: 5px solid #fd7e14; padding-left: 10px; background-color: #fff3cd; }")
        report_html.append("        .audit-Medium { border-left: 5px solid #ffc107; padding-left: 10px; background-color: #fff9e0; }")
        report_html.append("        .audit-Low { border-left: 5px solid #0dcaf0; padding-left: 10px; background-color: #cff4fc; }")
        report_html.append("        .audit-Info { border-left: 5px solid #adb5bd; padding-left: 10px; background-color: #e2e3e5; }")
        report_html.append("    </style>")
        report_html.append("</head>")
        report_html.append("<body>")
        report_html.append(f"<h1>FortiGate Analysis Report</h1>")
        report_html.append(f"<p><strong>Configuration File:</strong> {file_name}</p>")
        report_html.append(f"<p><strong>Detected Version:</strong> {model.fortios_version or 'Not Found'}</p>")

        # --- Summary Section --- 
        if st.session_state.summary_data:
            summary_data = st.session_state.summary_data
            report_html.append("<h2>Configuration Summary</h2>")
            report_html.append("<div class='summary-grid'>")
            if summary_data['parsed_counts']:
                for name, count in summary_data['parsed_counts'].items():
                     report_html.append(f"<div class='summary-item'><span class='label'>{name} (Parsed)</span><span class='value'>{count}</span></div>")
            report_html.append("</div>")
            # Add other summary parts (complexity, high usage etc.) if desired
            # ... (Could add more details from summary_data here)

        # --- Audit Findings Section --- 
        if st.session_state.audit_findings:
            report_html.append("<h2>Audit Findings</h2>")
            audit_findings = st.session_state.audit_findings
            if audit_findings:
                import pandas as pd
                df_audit = pd.DataFrame(audit_findings)
                severity_levels = ["Critical", "High", "Medium", "Low", "Info"]
                if 'severity' in df_audit.columns:
                     for level in severity_levels:
                         df_level = df_audit[df_audit['severity'] == level]
                         if not df_level.empty:
                             report_html.append(f"<h3 class='audit-{level}'>{level} Findings ({len(df_level)})</h3>")
                             # Select and rename columns for the report table
                             report_cols = [col for col in ['category', 'message', 'object_name'] if col in df_level.columns]
                             df_display_audit = df_level[report_cols]
                             report_html.append(df_display_audit.to_html(escape=True, index=False, border=0)) # Use escape=True for safety
                else:
                     report_html.append("<h3>Findings (Severity Missing)</h3>")
                     report_html.append(df_audit.to_html(escape=True, index=False, border=0))
            else:
                report_html.append("<p>No significant audit findings.</p>")

        # --- Diagram Link Section --- 
        report_html.append("<h2>Network Diagram</h2>")
        if st.session_state.diagram_file_path:
            diagram_filename = os.path.basename(st.session_state.diagram_file_path)
            legend_filename = os.path.basename(st.session_state.legend_file_path) if st.session_state.legend_file_path else None
            report_html.append(f"<p>Diagram generated: <strong>{diagram_filename}</strong></p>")
            if legend_filename:
                report_html.append(f"<p>Legend generated: <strong>{legend_filename}</strong></p>")
            report_html.append("<p><i>Note: The diagram image is saved separately in the same directory where the application was run.</i></p>")
        else:
            report_html.append("<p>Diagram was not generated or generation failed.</p>")

        # --- Unused Objects Section --- 
        if st.session_state.unused_report_data:
            report_html.append("<h2>Unused Objects</h2>")
            unused_data = st.session_state.unused_report_data
            has_unused = False
            unused_list_html = ["<ul>"]
            for key, items in unused_data.items():
                if items:
                    has_unused = True
                    # Format key nicely (e.g., addr_groups -> Address Groups)
                    title = key.replace('_', ' ').title()
                    unused_list_html.append(f"<li><strong>{title}:</strong> {', '.join(items)}</li>")
            unused_list_html.append("</ul>")
            if has_unused:
                report_html.extend(unused_list_html)
            else:
                report_html.append("<p>No potentially unused objects found based on analysis scope.</p>")

        # --- Connectivity Tree Section --- 
        if st.session_state.connectivity_tree:
            report_html.append("<h2>Interface Connectivity Tree</h2>")
            report_html.append(f"<pre>{st.session_state.connectivity_tree}</pre>")

        # --- Configuration Tables Section --- 
        report_html.append("<h2>Configuration Details</h2>")
        # Add tables similar to the tabs
        try:
            # --- Interfaces Table ---
            report_html.append("<h3>System Interfaces</h3>")
            intf_list = [{**v, 'name': k} for k, v in model.interfaces.items()]
            intf_cols = ['name', 'ip', 'type', 'description', 'alias', 'role', 'vdom', 'status', 'allowaccess', 'secondary_ip']
            intf_display_cols = {
                'name': 'Name', 'ip': 'IP/Mask', 'type': 'Type', 'description': 'Description',
                'alias': 'Alias', 'role': 'Role', 'vdom': 'VDOM', 'status': 'Status',
                'allowaccess': 'Allow Access', 'secondary_ip': 'Secondary IPs'
            }
            df_intf = get_table_dataframe(intf_list, intf_cols, intf_display_cols)
            list_cols_to_convert = ['Allow Access', 'Secondary IPs', 'Alias']
            for col_name in list_cols_to_convert:
                if col_name in df_intf.columns:
                     df_intf[col_name] = df_intf[col_name].apply(
                         lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x
                     )
            report_html.append(df_intf.to_html(escape=True, index=False, border=0))

            # --- Zones Table ---
            report_html.append("<h3>Firewall Zones</h3>")
            zone_list = [{**v, 'name': k} for k, v in model.zones.items()]
            zone_cols = ['name', 'interface', 'intrazone']
            zone_display_cols = {'name': 'Name', 'interface': 'Members', 'intrazone': 'Intrazone Action'}
            df_zone = get_table_dataframe(zone_list, zone_cols, zone_display_cols)
            report_html.append(df_zone.to_html(escape=True, index=False, border=0))

            # --- Static Routes Table ---
            report_html.append("<h3>Static Routes</h3>")
            route_list = model.routes
            route_cols = ['name', 'dst', 'gateway', 'device', 'distance', 'priority', 'status', 'comment']
            route_display_cols = {
                'name': 'Name/Seq', 'dst': 'Destination', 'gateway': 'Gateway', 'device': 'Interface',
                'distance': 'Distance', 'priority': 'Priority', 'status': 'Status', 'comment': 'Comment'
            }
            df_route = get_table_dataframe(route_list, route_cols, route_display_cols)
            report_html.append(df_route.to_html(escape=True, index=False, border=0))

            # --- Policies Table ---
            report_html.append("<h3>Firewall Policies</h3>")
            pol_list = model.policies
            pol_cols = ['id', 'name', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'action', 'status', 'nat', 'ippool', 'poolname', 'logtraffic', 'comments']
            pol_display_cols = {
                'id': 'ID', 'name': 'Name', 'srcintf': 'Src Intf', 'dstintf': 'Dst Intf',
                'srcaddr': 'Src Addr', 'dstaddr': 'Dst Addr', 'service': 'Service',
                'action': 'Action', 'status': 'Status', 'nat': 'NAT', 'ippool': 'IP Pool',
                'poolname': 'Pool Name', 'logtraffic': 'Log', 'comments': 'Comments'
            }
            df_pol = get_table_dataframe(pol_list, pol_cols, pol_display_cols)
            for col in ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service']:
                if col in df_pol.columns:
                    df_pol[col] = df_pol[col].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)
            report_html.append(df_pol.to_html(escape=True, index=False, border=0))

            # --- Addresses Table ---
            report_html.append("<h3>Address Objects</h3>")
            addr_list = [{**v, 'obj_name': k} for k, v in model.addresses.items()]
            addr_cols = ['obj_name', 'type', 'subnet', 'fqdn', 'start_ip', 'end_ip', 'wildcard', 'comment']
            addr_display_cols = {
                'obj_name': 'Name', 'type': 'Type', 'subnet': 'Subnet', 'fqdn': 'FQDN',
                'start_ip': 'Start IP', 'end_ip': 'End IP', 'wildcard': 'Wildcard', 'comment': 'Comment'
            }
            df_addr = get_table_dataframe(addr_list, addr_cols, addr_display_cols)
            report_html.append(df_addr.to_html(escape=True, index=False, border=0))

            # --- Address Groups Table ---
            report_html.append("<h3>Address Groups</h3>")
            addrgrp_list = [{'name': k, 'member': v} for k, v in model.addr_groups.items()]
            addrgrp_cols = ['name', 'member']
            addrgrp_display_cols = {'name': 'Name', 'member': 'Members'}
            df_addrgrp = get_table_dataframe(addrgrp_list, addrgrp_cols, addrgrp_display_cols)
            if 'Members' in df_addrgrp.columns:
                 df_addrgrp['Members'] = df_addrgrp['Members'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)
            report_html.append(df_addrgrp.to_html(escape=True, index=False, border=0))

            # --- Services Table ---
            report_html.append("<h3>Custom Services</h3>")
            svc_list = [{**v, 'obj_name': k} for k, v in model.services.items()]
            svc_cols = ['obj_name', 'protocol', 'port', 'tcp_portrange', 'udp_portrange', 'icmptype', 'icmpcode', 'comment']
            svc_display_cols = {
                'obj_name': 'Name', 'protocol': 'Protocol', 'port': 'Port Info (Combined)',
                'tcp_portrange': 'TCP Ports', 'udp_portrange': 'UDP Ports',
                'icmptype': 'ICMP Type', 'icmpcode': 'ICMP Code', 'comment': 'Comment'
            }
            df_svc = get_table_dataframe(svc_list, svc_cols, svc_display_cols)
            svc_list_cols = ['Port Info (Combined)', 'TCP Ports', 'UDP Ports']
            for col_name in svc_list_cols:
                if col_name in df_svc.columns:
                    df_svc[col_name] = df_svc[col_name].apply(
                        lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x
                    )
            report_html.append(df_svc.to_html(escape=True, index=False, border=0))

            # --- Service Groups Table ---
            report_html.append("<h3>Service Groups</h3>")
            svcgrp_list = [{'name': k, 'member': v} for k, v in model.svc_groups.items()]
            svcgrp_cols = ['name', 'member']
            svcgrp_display_cols = {'name': 'Name', 'member': 'Members'}
            df_svcgrp = get_table_dataframe(svcgrp_list, svcgrp_cols, svcgrp_display_cols)
            if 'Members' in df_svcgrp.columns:
                 df_svcgrp['Members'] = df_svcgrp['Members'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)
            report_html.append(df_svcgrp.to_html(escape=True, index=False, border=0))

            # --- VIPs Table ---
            report_html.append("<h3>Virtual IPs (VIPs)</h3>")
            vip_list = [{**v, 'name': k} for k, v in model.vips.items()]
            vip_cols = ['name', 'extip', 'mappedip', 'extintf', 'portforward', 'protocol', 'extport', 'mappedport', 'comment']
            vip_display_cols = {
                'name': 'Name', 'extip': 'External IP', 'mappedip': 'Mapped IP(s)',
                'extintf': 'Ext Interface', 'portforward': 'Port Fwd', 'protocol': 'Protocol',
                'extport': 'Ext Port', 'mappedport': 'Mapped Port', 'comment': 'Comment'
            }
            df_vip = get_table_dataframe(vip_list, vip_cols, vip_display_cols)
            if 'Mapped IP(s)' in df_vip.columns:
                df_vip['Mapped IP(s)'] = df_vip['Mapped IP(s)'].apply(lambda x: ', '.join([item.get('range','?') for item in x]) if isinstance(x, list) else x)
            report_html.append(df_vip.to_html(escape=True, index=False, border=0))

            # Add other tables as needed (VPN, DHCP, DNS, NTP, Admins, Security Profiles etc.)
            # ... (Example: Admins)
            report_html.append("<h3>Administrators</h3>")
            admin_list = [{**v, 'name': k} for k, v in model.admins.items()]
            admin_cols = ['name', 'accprofile', 'trusted_hosts', 'vdoms']
            admin_display_cols = {'name': 'Name', 'accprofile': 'Access Profile', 'trusted_hosts': 'Trusted Hosts', 'vdoms': 'VDOMs'}
            df_admin = get_table_dataframe(admin_list, admin_cols, admin_display_cols)
            if 'Trusted Hosts' in df_admin.columns:
                df_admin['Trusted Hosts'] = df_admin['Trusted Hosts'].apply(
                    lambda x: ', '.join(map(str, x)) if isinstance(x, list) and x else 'Any'
                )
            if 'VDOMs' in df_admin.columns:
                df_admin['VDOMs'] = df_admin['VDOMs'].apply(
                    lambda x: ', '.join(map(str, x)) if isinstance(x, list) and x else (x if x else '-')
                )
            report_html.append(df_admin.to_html(escape=True, index=False, border=0))

            # ... (Add more tables here following the pattern) ...

        except Exception as report_table_e:
            st.error(f"Error generating tables for report: {report_table_e}")
            report_html.append(f"<p><strong>Error generating table section:</strong> {report_table_e}</p>")

        # --- Finish HTML --- 
        report_html.append("</body>")
        report_html.append("</html>")

        final_html_content = "\n".join(report_html)

        # --- Provide Download Button based on selected format --- 
        if export_format == 'HTML':
            report_filename = f"FortiGate_Analysis_{file_name}.html"
            st.download_button(
                label="📥 Download HTML Report",
                data=final_html_content,
                file_name=report_filename,
                mime="text/html"
            )
        elif export_format == 'PDF':
            report_filename = f"FortiGate_Analysis_{file_name}.pdf"
            pdf_buffer = BytesIO()
            # Convert HTML to PDF
            pisa_status = pisa.CreatePDF(
                final_html_content,                # Source HTML string
                dest=pdf_buffer)                   # Destination buffer

            # Check if PDF creation was successful
            if not pisa_status.err:
                pdf_buffer.seek(0)
                st.download_button(
                    label="📥 Download PDF Report",
                    data=pdf_buffer,
                    file_name=report_filename,
                    mime="application/pdf"
                )
            else:
                st.error(f"Error generating PDF: {pisa_status.err}")
                st.error("Could not convert HTML to PDF. Please try exporting as HTML.")
                # Optionally show the raw HTML for debugging
                # with st.expander("Raw HTML Content (for debugging PDF error)"):
                #    st.code(final_html_content, language='html')

    else:
        st.sidebar.warning("Analysis data not found in session state.")


# --- Main Area for Results ---
if run_analysis and uploaded_file is not None:
    st.header("Processing Results")

    # Check if we need to parse the file (only if model1 is not already in session state)
    if st.session_state.model1 is None:
        # Read file content
        stringio = io.StringIO(uploaded_file.getvalue().decode("utf-8"))
        config_lines = stringio.readlines()
        main_status = st.status(f"Parsing {st.session_state.uploaded_file_name_1}...", expanded=True)
        try:
            main_status.write(f"Parsing configuration file...")
            parser = FortiParser(config_lines)
            st.session_state.model1 = parser.parse() # Store model in session state
            main_status.write("Parsing complete.")
            st.write(f"Detected FortiOS Version: {st.session_state.model1.fortios_version if st.session_state.model1.fortios_version else 'Not Found'}")
            main_status.update(label="Parsing complete.", state="complete", expanded=False)
            st.session_state.analysis_done = False # Ensure analysis runs after parsing
            st.session_state.trace_done = False    # Ensure trace runs after parsing
            st.session_state.processing_error = False # Reset error state on successful parse
        except ImportError as import_err: # Catch import errors for primary modules
            st.session_state.processing_error = True
            if 'main_status' in locals(): main_status.update(label=f"Initialisation Error (Missing Module: {import_err})", state="error", expanded=True)
            st.error(f"Error importing core modules: {import_err}")
            st.error("Please ensure fortiparser.py, config_model.py, diagram_generator.py, and utils.py are available and required dependencies (like 'pandas') are installed.")
            st.code(traceback.format_exc())
            st.stop()
        except Exception as parse_e:
            st.session_state.processing_error = True
            if 'main_status' in locals(): main_status.update(label=f"Critical Parsing Error: {parse_e}", state="error", expanded=True)
            st.error(f"Critical parsing error: {parse_e}")
            st.error("The application could not understand the structure of the configuration file. Please verify the file format.")
            st.code(traceback.format_exc()) # Show detailed traceback
            st.stop() # Stop if parsing fails critically

    # --- Processing Logic (Analysis or Trace) ---
    # Only run if model exists and analysis/trace hasn't been done or requested again
    if st.session_state.model1 and not st.session_state.processing_error:

        # Initialise Generator/Auditor using the model from session state
        generator = NetworkDiagramGenerator(st.session_state.model1)
        auditor = ConfigAuditor(st.session_state.model1)

        # Determine if we need to run processing (analysis or trace)
        should_run_processing = False
        if run_trace and not st.session_state.trace_done:
            should_run_processing = True
            process_type = "trace"
        elif not run_trace and not st.session_state.analysis_done:
            should_run_processing = True
            process_type = "analysis"

        if should_run_processing:
            main_status = st.status(f"Running {process_type}...", expanded=True)
            st.session_state.processing_error = False # Reset error flag before processing

            try:
                # --- Path Tracing Logic ---
                if process_type == "trace":
                    main_status.update(label="Performing Network Path Trace...", state="running", expanded=True)
                    st.info("Performing Network Path Trace...") # Keep user informed
                    if not all([trace_src, trace_dst, trace_port]):
                        st.warning("Source IP, Destination IP, and Destination Port are required for tracing.")
                        main_status.update(label="Path trace skipped (Missing Parameters)", state="warning", expanded=False)
                        # Don't set trace_done=True here, allow retry if parameters are entered
                    else:
                        try:
                            path_result, status_msg = generator.trace_network_path(
                                source_ip=trace_src,
                                dest_ip=trace_dst,
                                dest_port=trace_port,
                                protocol=trace_proto.lower()
                            )
                            # Store trace results in session state
                            st.session_state.trace_result = path_result
                            st.session_state.trace_status_msg = status_msg
                            st.session_state.trace_done = True # Mark trace as complete for these parameters
                            main_status.update(label="Path trace complete.", state="complete", expanded=False)
                        except ValueError as ve:
                            st.session_state.processing_error = True
                            st.error(f"Error during path trace execution: {ve}")
                            st.error("Please ensure the provided IP addresses and port are valid.")
                            st.code(traceback.format_exc())
                            main_status.update(label="Path trace failed (Invalid Input).", state="error", expanded=False)
                        except Exception as trace_e:
                            st.session_state.processing_error = True
                            st.error(f"An unexpected error occurred during path trace: {trace_e}")
                            st.error("Please check the logs or the configuration file for potential issues.")
                            st.code(traceback.format_exc())
                            main_status.update(label="Path trace failed (Error).", state="error", expanded=False)

                # --- Analysis and Diagram Logic ---
                elif process_type == "analysis":
                    main_status.update(label="Analysing configuration and generating outputs...", state="running", expanded=True)

                    # --- Run Analysis, Audit, Diagram, Reports --- 
                    # (Error handling within each step)
                    analysis_step_error = False

                    # 1. Run Analysis
                    try:
                        main_status.write("Analysing object relationships...")
                        generator.analyze_relationships()
                        main_status.write("Analysis complete.")
                    except Exception as ana_e:
                        st.error(f"Error during relationship analysis: {ana_e}")
                        st.code(traceback.format_exc())
                        analysis_step_error = True

                    # 2. Run Audit
                    if not analysis_step_error:
                        try:
                            main_status.write("Running configuration audit...")
                            st.session_state.audit_findings = auditor.run_audit() # Store results
                            main_status.write("Audit complete.")
                        except Exception as aud_e:
                            st.error(f"Error during configuration audit: {aud_e}")
                            st.code(traceback.format_exc())
                            analysis_step_error = True

                    # 3. Generate Diagram
                    if not analysis_step_error:
                        try:
                            main_status.write("Generating network diagram...")
                            diagram_file = generator.generate_diagram(output_basename)
                            if diagram_file and os.path.exists(diagram_file):
                                st.session_state.diagram_file_path = diagram_file # Store path
                                main_status.write(f"Diagram saved: {diagram_file}")
                                # Store legend path
                                legend_file = f"{output_basename}_legend.png"
                                if os.path.exists(legend_file):
                                    st.session_state.legend_file_path = legend_file
                                else:
                                    st.session_state.legend_file_path = None
                            else:
                                main_status.write("Diagram generation did not produce a viewable file or failed.")
                                st.warning("Diagram generation did not produce a viewable file. Check logs or Graphviz installation.")
                                st.session_state.diagram_file_path = None
                                st.session_state.legend_file_path = None
                        except ImportError as import_err:
                             main_status.write(f"Diagram Generation Failed: Missing dependency - {import_err}")
                             st.error(f"Diagram Generation Failed: Missing dependency - {import_err}")
                             st.warning("Please ensure 'graphviz' (Python library) and 'pandas' are installed (`pip install graphviz pandas`).")
                             analysis_step_error = True
                        except subprocess.CalledProcessError as proc_err: # Catch Graphviz execution errors
                             main_status.write(f"Diagram Generation Failed: Graphviz error.")
                             st.error(f"Diagram Generation Failed: Graphviz executable ('dot') returned an error: {proc_err}")
                             st.error("Ensure Graphviz is installed correctly and the 'dot' command is in your system's PATH.")
                             st.code(proc_err.stderr.decode() if proc_err.stderr else "No stderr output from Graphviz.")
                             analysis_step_error = True
                        except FileNotFoundError: # Catch if 'dot' command isn't found
                             main_status.write("Diagram Generation Failed: Graphviz not found.")
                             st.error("Diagram Generation Failed: Graphviz executable ('dot') not found.")
                             st.error("Please install Graphviz for your operating system and ensure it's added to your system's PATH.")
                             st.info("See installation instructions: https://graphviz.org/download/")
                             analysis_step_error = True
                        except Exception as diag_e:
                             main_status.write(f"Diagram Generation Failed: Unexpected error.")
                             st.error(f"An unexpected error occurred during diagram generation: {diag_e}")
                             st.code(traceback.format_exc())
                             analysis_step_error = True

                    # 4. Generate Reports (Unused, Summary, Connectivity)
                    if not analysis_step_error:
                        try:
                            main_status.write("Generating reports...")
                            st.session_state.unused_report_data = generator.generate_unused_report(output_basename)
                            st.session_state.summary_data = generator.generate_relationship_summary()
                            st.session_state.connectivity_tree = generator.generate_connectivity_tree()
                            main_status.write("Reports generated.")
                        except Exception as report_e:
                             main_status.write("Report Generation Failed.")
                             st.error(f"An error occurred during report generation: {report_e}")
                             st.code(traceback.format_exc())
                             analysis_step_error = True # Mark error for this step

                    # --- Final Analysis Status Update ---
                    if not analysis_step_error:
                        st.session_state.analysis_done = True # Mark analysis as complete
                        main_status.update(label="Analysis processing complete.", state="complete", expanded=False)
                    else:
                        st.session_state.processing_error = True # Set global error flag if any step failed
                        main_status.update(label="Analysis processing failed (Error).", state="error", expanded=True)

            except ImportError as import_err:
                 st.session_state.processing_error = True
                 main_status.update(label=f"Analysis/Generation Failed (Missing Dependency: {import_err})", state="error", expanded=True)
                 st.error(f"Analysis/Generation Failed: Missing dependency - {import_err}")
                 st.warning("Please ensure 'graphviz' (Python library and system binaries) and 'pandas' are installed (`pip install graphviz pandas`).")
            except Exception as gen_e:
                st.session_state.processing_error = True
                main_status.update(label="Analysis/Generation Failed (Error)", state="error", expanded=True)
                st.error(f"Error during analysis/generation: {gen_e}")
                st.error("There was an issue processing the configuration after parsing. Check the details below.")
                st.code(traceback.format_exc())

        # --- Display Results (Reading from Session State) ---

        # Display Trace Results if available
        if run_trace and st.session_state.trace_done and not st.session_state.processing_error:
            st.subheader("Trace Result")
            st.write(f"**Status:** {st.session_state.trace_status_msg}")
            if st.session_state.trace_result:
                st.write("**Path Details (Simulated Hops):**")
                for hop_info in st.session_state.trace_result:
                    hop_md = f"**Hop {hop_info.get('hop')}: [{hop_info.get('type')}]**\\n"
                    details = []
                    if 'detail' in hop_info: details.append(f"- Detail: `{hop_info['detail']}`")
                    if 'interface' in hop_info: details.append(f"- Interface: `{hop_info['interface']}`")
                    if 'policy_id' in hop_info and hop_info['policy_id']: details.append(f"- Policy ID: `{hop_info['policy_id']}`")
                    if 'egress_interface' in hop_info: details.append(f"- Egress IF: `{hop_info['egress_interface']}`")
                    if 'post_nat_src' in hop_info and hop_info.get('pre_nat_src') != hop_info.get('post_nat_src'): details.append(f"- NAT Src: `{hop_info.get('pre_nat_src')} -> {hop_info.get('post_nat_src')}`")
                    if 'post_nat_dst' in hop_info and hop_info.get('pre_nat_dst') != hop_info.get('post_nat_dst'): details.append(f"- NAT Dst: `{hop_info.get('pre_nat_dst')} -> {hop_info.get('post_nat_dst')}`")
                    if 'post_nat_port' in hop_info and hop_info.get('pre_nat_port') != hop_info.get('post_nat_port'): details.append(f"- NAT Port: `{hop_info.get('pre_nat_port')} -> {hop_info.get('post_nat_port')}`")
                    if details:
                        hop_md += "\\n".join(details)
                    st.markdown(hop_md)
                    st.markdown("---") # Separator between hops
        elif run_trace and not st.session_state.trace_done and not st.session_state.processing_error:
             st.info("Enter trace parameters and click 'Parse & Analyse Configuration' again to run the trace.")

        # Display Analysis Results if available (and not tracing)
        elif not run_trace and st.session_state.analysis_done and not st.session_state.processing_error:
            # --- Display Audit Findings --- 
            with st.expander("Configuration Audit Findings", expanded=True):
                if st.session_state.audit_findings:
                    import pandas as pd
                    df_audit = pd.DataFrame(st.session_state.audit_findings)
                    desired_cols_ordered = ['severity', 'category', 'message', 'object_name']
                    present_cols = [col for col in desired_cols_ordered if col in df_audit.columns]
                    if present_cols:
                        df_display = df_audit[present_cols]
                        severity_levels = ["Critical", "High", "Medium", "Low", "Info"]
                        has_severity_col = 'severity' in df_display.columns
                        found_findings = False
                        for level in severity_levels:
                            if has_severity_col:
                                df_level = df_display[df_display['severity'] == level]
                                cols_to_show = [col for col in df_display.columns if col != 'severity']
                                if not df_level.empty:
                                    st.write(f"{level} Findings:")
                                    st.dataframe(df_level[cols_to_show], use_container_width=True)
                                    found_findings = True
                        if not found_findings and has_severity_col:
                            st.success("No audit findings in defined severity levels.")
                        elif not has_severity_col and not df_display.empty: # Display if severity missing but data exists
                            st.warning("Audit Findings (Severity column missing):")
                            st.dataframe(df_display, use_container_width=True)
                            found_findings = True
                    else:
                        st.warning("Could not format audit findings. Displaying raw data:")
                        st.json(st.session_state.audit_findings)
                        found_findings = True

                    if not found_findings: # Handle cases where df_audit might be non-empty but processing failed
                         st.success("No significant audit findings.")

                else:
                    st.success("No significant audit findings.")

            # --- Display Diagram --- 
            if st.session_state.diagram_file_path:
                diagram_file = st.session_state.diagram_file_path
                # Determine file type
                file_type = None
                mime_type = None
                if diagram_file.lower().endswith(('.png', '.jpg', '.jpeg')):
                    file_type = 'png'
                    mime_type = 'image/png'
                elif diagram_file.lower().endswith('.svg'):
                    file_type = 'svg'
                    mime_type = 'image/svg+xml'

                # Display Download Button
                if file_type and mime_type:
                    try:
                        with open(diagram_file, "rb") as fp:
                            st.download_button(
                                label=f"Download Diagram ({file_type.upper()})",
                                data=fp,
                                file_name=os.path.basename(diagram_file),
                                mime=mime_type
                            )
                    except Exception as dl_e:
                        st.error(f"Error preparing diagram download button: {dl_e}")

                # Display Diagram Image
                st.subheader("Network Diagram")
                if file_type == 'png':
                    st.image(diagram_file, caption="Network Diagram", use_container_width=True)
                elif file_type == 'svg':
                    try:
                        with open(diagram_file, 'r', encoding='utf-8') as f_svg:
                            svg_content = f_svg.read()
                        st.image(svg_content, caption="Network Diagram (SVG)", use_container_width=True)
                    except Exception as svg_e:
                        st.error(f"Error reading or displaying SVG diagram: {svg_e}")
                else:
                    st.warning(f"Diagram generated ({diagram_file}), but preview for this format is not supported. Check the file directly.")

                # Display Legend
                if st.session_state.legend_file_path:
                    st.image(st.session_state.legend_file_path, caption="Diagram Legend")
            else:
                st.info("Diagram was not generated or failed.")

            # --- Display Reports --- 
            # Unused Objects Report
            if st.session_state.unused_report_data:
                with st.expander("Unused Objects Report", expanded=False):
                    unused_report_data = st.session_state.unused_report_data
                    if any(unused_report_data.values()):
                        if unused_report_data.get('addresses'): st.markdown(f"**Unused Addresses:** {', '.join(unused_report_data['addresses'])}")
                        if unused_report_data.get('addr_groups'): st.markdown(f"**Unused Address Groups:** {', '.join(unused_report_data['addr_groups'])}")
                        if unused_report_data.get('services'): st.markdown(f"**Unused Services:** {', '.join(unused_report_data['services'])}")
                        if unused_report_data.get('svc_groups'): st.markdown(f"**Unused Service Groups:** {', '.join(unused_report_data['svc_groups'])}")
                        if unused_report_data.get('interfaces'): st.markdown(f"**Unused Interfaces:** {', '.join(unused_report_data['interfaces'])}")
                        if unused_report_data.get('zones'): st.markdown(f"**Unused Zones:** {', '.join(unused_report_data['zones'])}")
                        if unused_report_data.get('vips'): st.markdown(f"**Unused VIPs:** {', '.join(unused_report_data['vips'])}")
                        if unused_report_data.get('ippools'): st.markdown(f"**Unused IP Pools:** {', '.join(unused_report_data['ippools'])}")
                        if unused_report_data.get('routes'): st.markdown(f"**Unused Static Routes:** {', '.join(unused_report_data['routes'])}")
                        if unused_report_data.get('phase1'): st.markdown(f"**Unused VPN Phase 1:** {', '.join(unused_report_data['phase1'])}")
                        if unused_report_data.get('phase2'): st.markdown(f"**Unused VPN Phase 2:** {', '.join(unused_report_data['phase2'])}")
                    else:
                        st.success("No potentially unused objects found based on analysis scope.")
            else:
                 with st.expander("Unused Objects Report", expanded=False):
                     st.info("Unused object report data not available.")

            # Relationship Summary
            if st.session_state.summary_data:
                st.subheader("Relationship Summary")
                summary_data = st.session_state.summary_data
                with st.expander("Object Counts (Parsed)", expanded=False):
                    if summary_data['parsed_counts']:
                        cols = st.columns(3)
                        col_idx = 0
                        for name, count in summary_data['parsed_counts'].items():
                            cols[col_idx].metric(label=name, value=count)
                            col_idx = (col_idx + 1) % 3
                    else:
                        st.write("No objects parsed.")
                with st.expander("Object Counts (Used & Drawn)", expanded=False):
                    if summary_data['used_counts']:
                        cols = st.columns(3)
                        col_idx = 0
                        for name, count in summary_data['used_counts'].items():
                            cols[col_idx].metric(label=name, value=count)
                            col_idx = (col_idx + 1) % 3
                    else:
                        st.write("No objects found to be used in the drawn diagram scope.")

                with st.expander("Grouping Complexity", expanded=False):
                    complexity = summary_data['grouping_complexity']
                    st.metric("Max Address Group Nesting Depth", complexity['max_address_group_depth'])
                    st.metric("Max Service Group Nesting Depth", complexity['max_service_group_depth'])
                    if complexity['address_group_cycles']:
                        st.warning(f"Cycle detected involving Address Group(s): {', '.join(complexity['address_group_cycles'])}")
                    if complexity['service_group_cycles']:
                        st.warning(f"Cycle detected involving Service Group(s): {', '.join(complexity['service_group_cycles'])}")

                with st.expander("High Usage Objects (Top 5 by Policy Reference)", expanded=False):
                    import pandas as pd # Ensure pandas is available here too
                    high_usage = summary_data['high_usage_objects']
                    st.write("**Interfaces/Zones/Tunnels:**")
                    if high_usage['interfaces']:
                        df_intf_usage = pd.DataFrame(high_usage['interfaces'], columns=['Object', 'Policies'])
                        st.dataframe(df_intf_usage, use_container_width=True)
                    else: st.write("_(None)_ ")
                    st.write("**Addresses/Groups/VIPs:**")
                    if high_usage['addresses']:
                        df_addr_usage = pd.DataFrame(high_usage['addresses'], columns=['Object', 'Policies'])
                        st.dataframe(df_addr_usage, use_container_width=True)
                    else: st.write("_(None)_ ")
                    st.write("**Services/Groups:**")
                    if high_usage['services']:
                        df_svc_usage = pd.DataFrame(high_usage['services'], columns=['Object', 'Policies'])
                        st.dataframe(df_svc_usage, use_container_width=True)
                    else: st.write("_(None)_ ")

                with st.expander("Potentially Unused Objects Summary", expanded=False):
                    unused = summary_data['unused_counts']
                    if unused.get("_has_unused"):
                        cols = st.columns(3)
                        col_idx = 0
                        for name, count in unused.items():
                            if name != "_has_unused":
                                cols[col_idx].metric(label=name, value=count)
                                col_idx = (col_idx + 1) % 3
                        st.caption("See separate unused report file/expander for details")
                    else:
                        st.success("No potentially unused objects identified based on analysis scope.")

                with st.expander("Configuration Audit Summary", expanded=False):
                    audit = summary_data['audit_summary']
                    if audit['total_findings'] > 0:
                        st.metric("Total Potential Issues Found", audit['total_findings'])
                        st.write("**Findings by Severity:**")
                        cols = st.columns(len(audit['severity_counts']))
                        col_idx = 0
                        # Sort severity for consistent display
                        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}
                        sorted_severities = sorted(audit['severity_counts'].items(), key=lambda item: severity_order.get(item[0], 99))
                        for sev, count in sorted_severities:
                            cols[col_idx].metric(label=sev, value=count)
                            col_idx += 1
                        st.caption("See audit findings expander/section for details")
                    else:
                        st.success("No potential issues identified by the audit.")
            else:
                st.info("Relationship summary data not available.")

            # Connectivity Tree
            if st.session_state.connectivity_tree:
                with st.expander("Interface Connectivity Tree", expanded=False):
                    st.code(st.session_state.connectivity_tree, language='text')
            else:
                 with st.expander("Interface Connectivity Tree", expanded=False):
                     st.info("Connectivity tree data not available.")

            # --- Generate and Display Tables --- 
            st.subheader("Configuration Tables (Summary)")
            try:
                # Use tabs for better organisation of tables
                tab_titles = [
                    "Interfaces", "Zones", "Static Routes", "Policies",
                    "Addresses", "Addr Groups", "Services", "Svc Groups",
                    "VIPs", "IP Pools", "VPN P1", "VPN P2", "DHCP",
                    "DNS", "NTP", "Admins", "Antivirus", "IPS", "Web Filter", "App Control",
                    "RADIUS Servers", "LDAP Servers"
                ]
                tabs = st.tabs(tab_titles)
                model = st.session_state.model1 # Use model from session state

                # --- Interfaces Table --- 
                with tabs[0]:
                    st.write("System Interfaces")
                    intf_list = [{**v, 'name': k} for k, v in model.interfaces.items()]
                    intf_cols = ['name', 'ip', 'type', 'description', 'alias', 'role', 'vdom', 'status', 'allowaccess', 'secondary_ip']
                    intf_display_cols = {
                        'name': 'Name', 'ip': 'IP/Mask', 'type': 'Type', 'description': 'Description',
                        'alias': 'Alias', 'role': 'Role', 'vdom': 'VDOM', 'status': 'Status',
                        'allowaccess': 'Allow Access', 'secondary_ip': 'Secondary IPs'
                    }
                    df_intf = get_table_dataframe(intf_list, intf_cols, intf_display_cols)
                    list_cols_to_convert = ['Allow Access', 'Secondary IPs', 'Alias']
                    for col_name in list_cols_to_convert:
                        if col_name in df_intf.columns:
                             df_intf[col_name] = df_intf[col_name].apply(
                                 lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x
                             )
                    st.dataframe(df_intf, use_container_width=True)

                # --- Zones Table --- 
                with tabs[1]:
                    st.write("Firewall Zones")
                    zone_list = [{**v, 'name': k} for k, v in model.zones.items()]
                    zone_cols = ['name', 'interface', 'intrazone']
                    zone_display_cols = {'name': 'Name', 'interface': 'Members', 'intrazone': 'Intrazone Action'}
                    df_zone = get_table_dataframe(zone_list, zone_cols, zone_display_cols)
                    st.dataframe(df_zone, use_container_width=True)

                # --- Static Routes Table --- 
                with tabs[2]:
                    st.write("Static Routes")
                    route_list = model.routes
                    route_cols = ['name', 'dst', 'gateway', 'device', 'distance', 'priority', 'status', 'comment']
                    route_display_cols = {
                        'name': 'Name/Seq', 'dst': 'Destination', 'gateway': 'Gateway', 'device': 'Interface',
                        'distance': 'Distance', 'priority': 'Priority', 'status': 'Status', 'comment': 'Comment'
                    }
                    df_route = get_table_dataframe(route_list, route_cols, route_display_cols)
                    st.dataframe(df_route, use_container_width=True)

                # --- Policies Table --- 
                with tabs[3]:
                    st.write("Firewall Policies")
                    pol_list = model.policies
                    pol_cols = ['id', 'name', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'action', 'status', 'nat', 'ippool', 'poolname', 'logtraffic', 'comments']
                    pol_display_cols = {
                        'id': 'ID', 'name': 'Name', 'srcintf': 'Src Intf', 'dstintf': 'Dst Intf',
                        'srcaddr': 'Src Addr', 'dstaddr': 'Dst Addr', 'service': 'Service',
                        'action': 'Action', 'status': 'Status', 'nat': 'NAT', 'ippool': 'IP Pool',
                        'poolname': 'Pool Name', 'logtraffic': 'Log', 'comments': 'Comments'
                    }
                    df_pol = get_table_dataframe(pol_list, pol_cols, pol_display_cols)
                    for col in ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service']:
                        if col in df_pol.columns:
                            df_pol[col] = df_pol[col].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)
                    st.dataframe(df_pol, use_container_width=True)

                # --- Addresses Table --- 
                with tabs[4]:
                    st.write("Address Objects")
                    addr_list = [{**v, 'obj_name': k} for k, v in model.addresses.items()]
                    addr_cols = ['obj_name', 'type', 'subnet', 'fqdn', 'start_ip', 'end_ip', 'wildcard', 'comment']
                    addr_display_cols = {
                        'obj_name': 'Name', 'type': 'Type', 'subnet': 'Subnet', 'fqdn': 'FQDN',
                        'start_ip': 'Start IP', 'end_ip': 'End IP', 'wildcard': 'Wildcard', 'comment': 'Comment'
                    }
                    df_addr = get_table_dataframe(addr_list, addr_cols, addr_display_cols)
                    st.dataframe(df_addr, use_container_width=True)

                # --- Address Groups Table --- 
                with tabs[5]:
                    st.write("Address Groups")
                    addrgrp_list = [{'name': k, 'member': v} for k, v in model.addr_groups.items()]
                    addrgrp_cols = ['name', 'member']
                    addrgrp_display_cols = {'name': 'Name', 'member': 'Members'}
                    df_addrgrp = get_table_dataframe(addrgrp_list, addrgrp_cols, addrgrp_display_cols)
                    if 'Members' in df_addrgrp.columns:
                         df_addrgrp['Members'] = df_addrgrp['Members'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)
                    st.dataframe(df_addrgrp, use_container_width=True)

                # --- Services Table --- 
                with tabs[6]:
                    st.write("Custom Services")
                    svc_list = [{**v, 'obj_name': k} for k, v in model.services.items()]
                    svc_cols = ['obj_name', 'protocol', 'port', 'tcp_portrange', 'udp_portrange', 'icmptype', 'icmpcode', 'comment']
                    svc_display_cols = {
                        'obj_name': 'Name', 'protocol': 'Protocol', 'port': 'Port Info (Combined)',
                        'tcp_portrange': 'TCP Ports', 'udp_portrange': 'UDP Ports',
                        'icmptype': 'ICMP Type', 'icmpcode': 'ICMP Code', 'comment': 'Comment'
                    }
                    df_svc = get_table_dataframe(svc_list, svc_cols, svc_display_cols)
                    svc_list_cols = ['Port Info (Combined)', 'TCP Ports', 'UDP Ports']
                    for col_name in svc_list_cols:
                        if col_name in df_svc.columns:
                            df_svc[col_name] = df_svc[col_name].apply(
                                lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x
                            )
                    st.dataframe(df_svc, use_container_width=True)

                # --- Service Groups Table --- 
                with tabs[7]:
                    st.write("Service Groups")
                    svcgrp_list = [{'name': k, 'member': v} for k, v in model.svc_groups.items()]
                    svcgrp_cols = ['name', 'member']
                    svcgrp_display_cols = {'name': 'Name', 'member': 'Members'}
                    df_svcgrp = get_table_dataframe(svcgrp_list, svcgrp_cols, svcgrp_display_cols)
                    if 'Members' in df_svcgrp.columns:
                         df_svcgrp['Members'] = df_svcgrp['Members'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)
                    st.dataframe(df_svcgrp, use_container_width=True)

                # --- VIPs Table --- 
                with tabs[8]:
                    st.write("Virtual IPs (VIPs)")
                    vip_list = [{**v, 'name': k} for k, v in model.vips.items()]
                    vip_cols = ['name', 'extip', 'mappedip', 'extintf', 'portforward', 'protocol', 'extport', 'mappedport', 'comment']
                    vip_display_cols = {
                        'name': 'Name', 'extip': 'External IP', 'mappedip': 'Mapped IP(s)',
                        'extintf': 'Ext Interface', 'portforward': 'Port Fwd', 'protocol': 'Protocol',
                        'extport': 'Ext Port', 'mappedport': 'Mapped Port', 'comment': 'Comment'
                    }
                    df_vip = get_table_dataframe(vip_list, vip_cols, vip_display_cols)
                    if 'Mapped IP(s)' in df_vip.columns:
                        df_vip['Mapped IP(s)'] = df_vip['Mapped IP(s)'].apply(lambda x: ', '.join([item.get('range','?') for item in x]) if isinstance(x, list) else x)
                    st.dataframe(df_vip, use_container_width=True)

                # --- IP Pools Table --- 
                with tabs[9]:
                    st.write("IP Pools")
                    pool_list = [{**v, 'name': k} for k, v in model.ippools.items()]
                    pool_cols = ['name', 'type', 'startip', 'endip', 'comment']
                    pool_display_cols = {'name': 'Name', 'type': 'Type', 'startip': 'Start IP', 'endip': 'End IP', 'comment': 'Comment'}
                    df_pool = get_table_dataframe(pool_list, pool_cols, pool_display_cols)
                    st.dataframe(df_pool, use_container_width=True)

                # --- VPN Phase 1 Table --- 
                with tabs[10]:
                    st.write("VPN Phase 1")
                    p1_list = [{**v, 'name': k} for k, v in model.phase1.items()]
                    p1_cols = ['name', 'interface', 'remote_gw', 'psksecret', 'proposal', 'mode', 'status', 'peerid', 'comments']
                    p1_display_cols = {
                        'name': 'Name', 'interface': 'Interface', 'remote_gw': 'Remote GW',
                        'psksecret': 'PSK', 'proposal': 'Proposal', 'mode': 'Mode',
                        'status': 'Status', 'peerid': 'Peer ID', 'comments': 'Comments'
                    }
                    df_p1 = get_table_dataframe(p1_list, p1_cols, p1_display_cols)
                    if 'PSK' in df_p1.columns: df_p1['PSK'] = '***'
                    # Convert Comment column to string
                    if 'Comments' in df_p1.columns:
                        df_p1['Comments'] = df_p1['Comments'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else str(x))
                    st.dataframe(df_p1, use_container_width=True)

                # --- VPN Phase 2 Table --- 
                with tabs[11]:
                    st.write("VPN Phase 2")
                    p2_list = [{**v, 'name': k} for k, v in model.phase2.items()]
                    p2_cols = ['name', 'phase1name', 'proposal', 'src_subnet', 'dst_subnet', 'src_name', 'dst_name', 'auto_negotiate', 'keylifeseconds', 'comments']
                    p2_display_cols = {
                        'name': 'Name', 'phase1name': 'Phase1 Name', 'proposal': 'Proposal',
                        'src_subnet': 'Src Subnet', 'dst_subnet': 'Dst Subnet',
                        'src_name': 'Src Name Obj', 'dst_name': 'Dst Name Obj',
                        'auto_negotiate': 'Auto Neg', 'keylifeseconds': 'Keylife (s)', 'comments': 'Comments'
                    }
                    df_p2 = get_table_dataframe(p2_list, p2_cols, p2_display_cols)
                    st.dataframe(df_p2, use_container_width=True)

                # --- DHCP Servers Table --- 
                with tabs[12]:
                    st.write("DHCP Servers")
                    dhcp_list = model.dhcp_servers # Already list of dicts
                    dhcp_cols = ['id', 'interface', 'ip_range_str', 'default_gateway', 'netmask', 'dns_service', 'status', 'reserved_addresses']
                    dhcp_display_cols = {
                        'id': 'ID', 'interface': 'Interface', 'ip_range_str': 'IP Range',
                        'default_gateway': 'Gateway', 'netmask': 'Netmask', 'dns_service': 'DNS Service',
                        'status': 'Status', 'reserved_addresses': 'Reserved IPs'
                    }
                    df_dhcp = get_table_dataframe(dhcp_list, dhcp_cols, dhcp_display_cols)
                    if 'Reserved IPs' in df_dhcp.columns:
                         df_dhcp['Reserved IPs'] = df_dhcp['Reserved IPs'].apply(lambda x: len(x) if isinstance(x, list) else 0)
                    st.dataframe(df_dhcp, use_container_width=True)

                # --- System DNS Table --- 
                with tabs[13]:
                    st.write("System DNS")
                    dns_data = [model.dns] if model.dns else []
                    dns_cols = ['primary', 'secondary', 'domain']
                    dns_display_cols = {'primary': 'Primary', 'secondary': 'Secondary', 'domain': 'Domain'}
                    df_dns = get_table_dataframe(dns_data, dns_cols, dns_display_cols)
                    st.dataframe(df_dns, use_container_width=True)

                # --- System NTP Table --- 
                with tabs[14]:
                    st.write("System NTP")
                    ntp_data = []
                    if model.ntp:
                        ntp_enabled = model.ntp.get('ntpsync') == 'enable'
                        server_mode = model.ntp.get('type','fortiguard')
                        server_details = model.ntp.get('ntpserver','FortiGuard Servers') if server_mode == 'fortiguard' else model.ntp.get('server','?')
                        ntp_data = [{'enabled': 'Yes' if ntp_enabled else 'No', 'mode': server_mode, 'server': server_details}]

                    ntp_cols = ['enabled', 'mode', 'server']
                    ntp_display_cols = {'enabled': 'Enabled', 'mode': 'Mode', 'server': 'Server(s)'}
                    df_ntp = get_table_dataframe(ntp_data, ntp_cols, ntp_display_cols)
                    st.dataframe(df_ntp, use_container_width=True)

                # --- Administrators Table --- 
                with tabs[15]:
                    st.write("Administrators")
                    admin_list = [{**v, 'name': k} for k, v in model.admins.items()]
                    admin_cols = ['name', 'accprofile', 'trusted_hosts', 'vdoms']
                    admin_display_cols = {'name': 'Name', 'accprofile': 'Access Profile', 'trusted_hosts': 'Trusted Hosts', 'vdoms': 'VDOMs'}
                    df_admin = get_table_dataframe(admin_list, admin_cols, admin_display_cols)

                    # Format trusted hosts and VDOMs for display
                    if 'Trusted Hosts' in df_admin.columns:
                        df_admin['Trusted Hosts'] = df_admin['Trusted Hosts'].apply(
                            lambda x: ', '.join(map(str, x)) if isinstance(x, list) and x else 'Any'
                        )
                    if 'VDOMs' in df_admin.columns:
                        df_admin['VDOMs'] = df_admin['VDOMs'].apply(
                            lambda x: ', '.join(map(str, x)) if isinstance(x, list) and x else (x if x else '-')
                        )
                    st.dataframe(df_admin, use_container_width=True)

                # --- Antivirus Profiles Table --- 
                with tabs[16]:
                    st.write("Antivirus Profiles")
                    av_list = [{**v, 'name': k} for k, v in model.antivirus.items()]
                    av_cols = ['name', 'comment', 'botnet_c_c_scan']
                    av_display_cols = {'name': 'Name', 'comment': 'Comment', 'botnet_c_c_scan': 'Botnet C&C Scan'}
                    df_av = get_table_dataframe(av_list, av_cols, av_display_cols)
                    if 'Botnet C&C Scan' in df_av.columns:
                         df_av['Botnet C&C Scan'] = df_av['Botnet C&C Scan'].apply(lambda x: 'Yes' if x == 'enable' else 'No')
                    # Convert Comment column to string
                    if 'Comment' in df_av.columns:
                        df_av['Comment'] = df_av['Comment'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else str(x))
                    st.dataframe(df_av, use_container_width=True)

                # --- IPS Sensors Table --- 
                with tabs[17]:
                    st.write("IPS Sensors")
                    ips_list = [{**v, 'name': k} for k, v in model.ips.items()]
                    ips_cols = ['name', 'comment']
                    ips_display_cols = {'name': 'Name', 'comment': 'Comment'}
                    df_ips = get_table_dataframe(ips_list, ips_cols, ips_display_cols)
                    if 'Comment' in df_ips.columns:
                        df_ips['Comment'] = df_ips['Comment'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else str(x))
                    st.dataframe(df_ips, use_container_width=True)

                # --- Web Filter Profiles Table --- 
                with tabs[18]:
                    st.write("Web Filter Profiles")
                    wf_list = [{**v, 'name': k} for k, v in model.web_filter.items()]
                    wf_cols = ['name', 'comment', 'fortiguard_category']
                    wf_display_cols = {'name': 'Name', 'comment': 'Comment', 'fortiguard_category': 'FortiGuard Category Action'}
                    df_wf = get_table_dataframe(wf_list, wf_cols, wf_display_cols)
                    # Fortiguard category data might be complex, just display raw for now
                    # Convert Comment column to string
                    if 'Comment' in df_wf.columns:
                        df_wf['Comment'] = df_wf['Comment'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else str(x))
                    st.dataframe(df_wf, use_container_width=True)

                # --- Application Control Profiles Table --- 
                with tabs[19]:
                    st.write("Application Control Profiles")
                    app_list = [{**v, 'name': k} for k, v in model.app_control.items()]
                    app_cols = ['name', 'comment']
                    app_display_cols = {'name': 'Name', 'comment': 'Comment'}
                    df_app = get_table_dataframe(app_list, app_cols, app_display_cols)
                    if 'Comment' in df_app.columns:
                        df_app['Comment'] = df_app['Comment'].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else str(x))
                    st.dataframe(df_app, use_container_width=True)

                # --- RADIUS Servers Table (Example - Add if model.radius_servers exists) ---
                if hasattr(model, 'radius_servers') and model.radius_servers:
                    with tabs[20]:
                        st.write("RADIUS Servers")
                        radius_list = [{**v, 'name': k} for k, v in model.radius_servers.items()]
                        radius_cols = ['name', 'server', 'secret']
                        radius_display_cols = {'name': 'Name', 'server': 'Server IP', 'secret': 'Secret'}
                        df_radius = get_table_dataframe(radius_list, radius_cols, radius_display_cols)
                        if 'Secret' in df_radius.columns: df_radius['Secret'] = '***'
                        st.dataframe(df_radius, use_container_width=True)

                # --- LDAP Servers Table (Example - Add if model.ldap_servers exists) ---
                if hasattr(model, 'ldap_servers') and model.ldap_servers:
                    with tabs[21]:
                        st.write("LDAP Servers")
                        ldap_list = [{**v, 'name': k} for k, v in model.ldap_servers.items()]
                        ldap_cols = ['name', 'server', 'cnid', 'dn', 'password']
                        ldap_display_cols = {'name': 'Name', 'server': 'Server IP', 'cnid': 'User ID Field', 'dn': 'Distinguished Name', 'password': 'Password'}
                        df_ldap = get_table_dataframe(ldap_list, ldap_cols, ldap_display_cols)
                        if 'Password' in df_ldap.columns: df_ldap['Password'] = '***'
                        st.dataframe(df_ldap, use_container_width=True)

            except Exception as table_e:
                # Don't set global processing error here, tables are supplementary
                st.error(f"An error occurred during table generation: {table_e}")
                st.code(traceback.format_exc())
        elif not run_trace and not st.session_state.analysis_done:
             st.info("Click 'Parse & Analyse Configuration' to generate analysis, diagrams, and reports.")
        elif st.session_state.processing_error:
            st.error("Processing failed. Please check the errors above.")

    elif uploaded_file is None:
         st.info("Please upload a configuration file using the sidebar.")
    elif st.session_state.processing_error:
         st.error("Processing failed during parsing. Please check the errors above or upload a valid file.")


# --- Comparison Logic ---
elif run_compare and uploaded_file is not None and uploaded_file_compare is not None:
    st.header("Configuration Comparison")
    comparison_error = False # Local flag for comparison block errors

    # --- Parse File 1 (if not already parsed) ---
    if st.session_state.model1 is None:
        main_status = st.status(f"Parsing {st.session_state.uploaded_file_name_1} for comparison...", expanded=True)
        try:
            stringio1 = io.StringIO(uploaded_file.getvalue().decode("utf-8"))
            config_lines1 = stringio1.readlines()
            parser1 = FortiParser(config_lines1)
            st.session_state.model1 = parser1.parse()
            main_status.update(label=f"Parsing {st.session_state.uploaded_file_name_1} complete.", state="complete", expanded=False)
            st.session_state.comparison_done = False # Reset comparison if re-parsing
        except Exception as parse_e1:
            comparison_error = True
            if 'main_status' in locals(): main_status.update(label=f"Parsing Error (File 1): {parse_e1}", state="error", expanded=True)
            st.error(f"Error parsing {st.session_state.uploaded_file_name_1}: {parse_e1}")
            st.code(traceback.format_exc())

    # --- Parse File 2 (if not already parsed) ---
    if not comparison_error and st.session_state.model2 is None:
        main_status = st.status(f"Parsing {st.session_state.uploaded_file_name_2} for comparison...", expanded=True)
        try:
            stringio2 = io.StringIO(uploaded_file_compare.getvalue().decode("utf-8"))
            config_lines2 = stringio2.readlines()
            parser2 = FortiParser(config_lines2)
            st.session_state.model2 = parser2.parse()
            main_status.update(label=f"Parsing {st.session_state.uploaded_file_name_2} complete.", state="complete", expanded=False)
            st.session_state.comparison_done = False # Reset comparison if re-parsing
        except Exception as parse_e2:
            comparison_error = True
            if 'main_status' in locals(): main_status.update(label=f"Parsing Error (File 2): {parse_e2}", state="error", expanded=True)
            st.error(f"Error parsing {st.session_state.uploaded_file_name_2}: {parse_e2}")
            st.code(traceback.format_exc())

    # --- Run Comparison (if models exist and comparison not done) ---
    if not comparison_error and st.session_state.model1 and st.session_state.model2 and not st.session_state.comparison_done:
        main_status = st.status(f"Comparing {st.session_state.uploaded_file_name_1} and {st.session_state.uploaded_file_name_2}...", expanded=True)
        try:
            main_status.write("Comparing models...")
            st.session_state.diff_results = compare_models(st.session_state.model1, st.session_state.model2)
            st.session_state.diff_formatted = format_diff_results(st.session_state.diff_results)
            st.session_state.comparison_done = True # Mark comparison as done
            main_status.update(label="Comparison complete.", state="complete", expanded=False)
        except Exception as comp_e:
            comparison_error = True
            if 'main_status' in locals(): main_status.update(label=f"Comparison Failed: {comp_e}", state="error", expanded=True)
            st.error(f"An error occurred during comparison: {comp_e}")
            st.code(traceback.format_exc())

    # --- Display Comparison Results (if available) ---
    if not comparison_error and st.session_state.comparison_done:
        st.subheader("Structured Configuration Differences")
        if st.session_state.diff_formatted:
            st.markdown(st.session_state.diff_formatted, unsafe_allow_html=True)
        else:
            # This case might occur if comparison ran but produced no diff_formatted (e.g., empty diff)
            st.info("Comparison ran, but no formatted differences were generated (possibly identical files or an issue in formatting).")
    elif not comparison_error and not st.session_state.comparison_done:
        # This case handles when parsing is done but comparison hasn't run (e.g., button wasn't clicked after file uploads)
        st.info("Files are parsed. Click 'Compare Configurations' again to see the differences.")
    elif comparison_error:
        st.error("Comparison could not be completed due to errors during parsing or comparison.")

# --- Handle Button Clicks Without Required Files ---
elif run_analysis and uploaded_file is None:
    st.warning("Please upload a configuration file first.")
elif run_compare and (uploaded_file is None or uploaded_file_compare is None):
    st.warning("Please upload two configuration files to compare.")

# Add footer or additional info if needed
st.sidebar.markdown("---")
st.sidebar.info("Developed for FortiGate configuration analysis.") 
