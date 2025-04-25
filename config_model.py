#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data model for storing parsed FortiGate configuration.
"""
import ipaddress

class ConfigModel:
    """Holds all parsed FortiGate objects and resolves references."""
    def __init__(self):
        self.routes            = []
        self.addresses         = {}
        self.addr_groups       = {}
        self.services          = {}
        self.svc_groups        = {}
        self.interfaces        = {}
        self.vlans             = {}
        self.zones             = {}
        self.policies          = []
        self.vips              = {}
        self.vip_groups        = {}
        self.ippools           = {}
        self.dhcp_servers      = []
        self.ospf              = {}
        self.bgp               = {}
        self.phase1            = {}
        self.phase2            = {}
        self.traffic_shapers   = {}
        self.shaper_per_ip     = {}
        self.dos_policies      = []
        self.snmp_sysinfo      = {}
        self.snmp_communities  = {}
        self.ldap_servers      = {}
        self.admins            = {}
        self.ha                = {}
        self.ntp               = {}
        self.dns               = {}
        self.ssl_settings      = {}
        self.ssl_portals       = {}
        self.ssl_policies      = []
        self.vrrp              = {}
        
        # New sections
        self.system_global     = {}  # Global system settings
        self.antivirus        = {}  # Antivirus profiles
        self.ips              = {}  # IPS profiles
        self.web_filter       = {}  # Web filter profiles
        self.app_control      = {}  # Application control profiles
        self.ssl_inspection   = {}  # SSL/SSH inspection profiles
        self.waf              = {}  # Web Application Firewall profiles
        self.email_filter     = {}  # Email filter profiles
        self.dlp              = {}  # Data Leak Prevention profiles
        self.voip             = {}  # VoIP profiles
        self.icap             = {}  # ICAP profiles
        self.gtp              = {}  # GTP profiles
        self.radius_servers   = {}  # RADIUS servers
        self.user_groups      = {}  # User groups
        self.schedule_groups  = {}  # Schedule groups
        self.schedule_onetime = {}  # One-time schedules
        self.schedule_recurring = {}  # Recurring schedules
        self.sniffer_profile  = {}  # Sniffer profiles
        self.wan_opt          = {}   # WAN optimization profiles
        self.fortitoken       = {}   # FortiToken configuration
        self.fortiguard       = {}    # FortiGuard settings
        self.log_settings     = {}     # Logging settings
        self.sd_wan           = {}     # SD-WAN configuration
        self.load_balance     = {}     # Server load balancing
        self.wireless_controller = {}  # Wireless controller settings
        self.switch_controller = {}   # Switch controller settings
        self.sandbox          = {}      # FortiSandbox settings
        self.certificate      = {}      # SSL certificates
        self.saml             = {}       # SAML settings
        self.fsso             = {}       # Fortinet Single Sign-On
        self.automation       = {}       # Security Fabric automation
        self.sdn_connector    = {}       # SDN connectors
        self.extender         = {}       # FortiExtender settings
        self.vpn_l2tp         = {}       # L2TP VPN settings
        self.vpn_pptp         = {}       # PPTP VPN settings
        self.vpn_ssl_client   = {}       # SSL VPN client settings
        self.system_replacemsg = {}       # Replacement messages
        self.system_accprofile = {}       # Admin access profiles
        self.system_api_user  = {}        # API users
        self.system_sso_admin = {}         # SSO admin settings
        self.system_password_policy = {}    # Password policy
        self.system_interface_policy = {}     # Interface policies
        self.system_csf        = {}            # Security Fabric settings
        self.system_central_mgmt = {}         # Central management settings
        self.system_auto_update = {}           # Auto-update settings
        self.system_session_ttl = {}            # Session TTL settings
        self.system_gre_tunnel = {}              # GRE tunnel settings
        self.system_ddns       = {}                # Dynamic DNS settings
        self.system_dns_database = {}              # DNS database settings
        self.system_dns_server = {}                # DNS server settings
        self.system_proxy_arp  = {}                  # Proxy ARP settings
        self.system_virtual_wire_pair = {}            # Virtual wire pair settings
        self.system_wccp      = {}                     # WCCP settings
        self.system_sit_tunnel = {}                     # SIT tunnel settings
        self.system_ipip_tunnel = {}                     # IPIP tunnel settings
        self.system_vxlan     = {}                         # VXLAN settings
        self.system_geneve    = {}                          # GENEVE settings
        self.system_network_visibility = {}                # Network visibility settings
        self.system_ptp       = {}                             # PTP settings
        self.system_tos_based_priority = {}                    # ToS-based priority settings
        self.system_email_server = {}                             # Email server settings
        self.system_dns_filter = {}                                # DNS filter settings
        self.system_ips_urlfilter_dns = {}                            # IPS URL filter DNS settings
        self.system_fortiguard = {}                                    # FortiGuard settings
        self.system_fm        = {}                                         # FortiManager settings
        self.system_fortianalyzer = {}                                     # FortiAnalyzer settings
        self.system_fortisandbox = {}                                        # FortiSandbox settings
        self.vdoms = {} # Dictionary to store VDOM-specific configurations
        self.has_vdoms = False # Flag to indicate if VDOMs were parsed

    def resolve_address(self, name):
        if name in self.addresses:
            return [self.addresses[name]['subnet']]
        if name in self.addr_groups:
            out = []
            for m in self.addr_groups[name]:
                out += self.resolve_address(m)
            return out
        return []

    def resolve_service(self, name):
        if name in self.services:
            svc = self.services[name]
            return [f"{svc['protocol']}/{svc['port']}"]
        if name in self.svc_groups:
            out = []
            for m in self.svc_groups[name]:
                out += self.resolve_service(m)
            return out
        return []

    def expand_policy(self, pol):
        ep = pol.copy()
        ep['src_subnets'] = []
        for a in pol['srcaddr']:
            ep['src_subnets'] += self.resolve_address(a)
        ep['dst_subnets'] = []
        for a in pol['dstaddr']:
            ep['dst_subnets'] += self.resolve_address(a)
        ep['services_expanded'] = []
        for s in pol['service']:
            ep['services_expanded'] += self.resolve_service(s)
        # Add pool name if present
        # Check if ippool is enabled first
        if pol.get('ippool') == 'enable':
             ep['poolname'] = pol.get('poolname', 'N/A') # Add poolname if exists

        return ep 
