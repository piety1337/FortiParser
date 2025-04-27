# FortiParser Web UI

A web-based interface for parsing, visualizing, and auditing FortiGate firewall configurations.

This tool allows you to:

*   Upload a FortiGate configuration file (`.conf` or `.txt`).
*   Visualize the network topology using Graphviz.
*   Perform basic configuration audits for common issues and best practices.
*   Trace simulated network paths through the configuration.
*   View configuration objects (Interfaces, Policies, Addresses, Services, etc.) in tables.
*   Generate reports (Unused Objects, Audit Findings, Summary, Connectivity Tree).

## Setup

1.  **Prerequisites:**
    *   Python 3.8+
    *   Graphviz: You need to install the Graphviz binaries separately for your operating system. Make sure the `dot` executable is in your system's PATH.

2.  **Clone the repository (or download the files):**
    ```bash
    git clone <your-repo-url> # Or download and extract the files
    cd FortiParser # Or your project directory
    ```
3.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Run the Streamlit application:**
    ```bash
    streamlit run app.py
    ```
2.  The application should open automatically in your web browser.
3.  Use the sidebar to:
    *   Upload your FortiGate configuration file.
    *   (Optional) Set a custom base name for output files (diagrams, reports).
    *   (Optional) Configure and enable Path Tracing.
4.  Click the "Parse & Analyze Configuration" button.
5.  Results (Diagram, Audit Findings, Reports, Tables) will be displayed in the main area.
    *   Diagrams and reports are also saved as files in the directory where you ran the command (e.g., `network_topology.png`, `network_topology_unused_report.txt`).

## Notes

*   The analysis and diagram generation focus on common configuration elements. Complex or less common features might not be fully represented.
*   Path tracing is a simulation based on static routes, firewall policies, and NAT rules found in the configuration. It does not account for dynamic routing state, traffic shaping, or other complex traffic manipulations.
*   The audit provides basic checks and should be used as a starting point for a thorough review. 
