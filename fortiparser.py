#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FortiGate Comprehensive Table Report Parser

Parses a FortiGate CLI configuration file and prints ASCII tables summarising
all network objects for easy analysis.
"""

import argparse
import re
import sys
import ipaddress
from graphviz import Digraph

class NetworkDiagramGenerator:
    """Generates network topology diagrams from FortiGate configuration."""
    
    def __init__(self, model):
        self.model = model
        self.graph = Digraph(comment='FortiGate Network Topology')
        self.graph.attr(rankdir='TB')  # Top to bottom layout for better network hierarchy
        self._setup_graph_attributes()
        self.address_groups_expanded = {}
        self.service_groups_expanded = {}
        self.processed_nodes = set()  # Track processed nodes to avoid duplicates
        self.relationship_stats = {
            'zone_interface_count': {},
            'policy_address_count': {},
            'policy_service_count': {},
            'address_group_depth': {},
            'service_group_depth': {},
            'interface_policy_count': {},
            'address_policy_count': {},
            'service_policy_count': {},
        }
        
    def _setup_graph_attributes(self):
        """Set up default graph styling with modern aesthetics."""
        # Global graph attributes for modern look
        self.graph.attr(
            compound='true',
            splines='spline',  # Use spline for smoother edges
            concentrate='false',  # Disable edge concentration for stability
            nodesep='0.5',    # Reduced spacing
            ranksep='0.7',    # Reduced spacing
            ratio='auto',     # Let graphviz determine the best ratio
            size='8.5,11',    # Standard page size
            fontname='Helvetica',
            bgcolor='white',
            pad='0.2',
            margin='0.2',
            overlap='scale',
            packmode='node',   # Better node packing
            sep='+8',         # Minimum separation between nodes
            esep='+6'         # Minimum separation between edge labels
        )
        
        # Modern node styling
        self.graph.attr('node',
            shape='box',
            style='rounded,filled',
            fontname='Helvetica',
            fontsize='10',
            margin='0.4,0.3',
            height='0.6',
            width='1.2',
            penwidth='1.5'
        )
        
        # Modern edge styling
        self.graph.attr('edge',
            fontname='Helvetica',
            fontsize='8',
            len='1.5',
            penwidth='1.0',
            arrowsize='0.8',
            color='#666666'
        )

        # Define cluster style defaults (to be applied when creating clusters)
        self.CLUSTER_STYLE = {
            'style': 'rounded',
            'color': '#dddddd',
            'penwidth': '2.0',
            'fontname': 'Helvetica Bold',
            'fontsize': '12',
            'margin': '16'
        }
        
        # Modern color scheme and styling for different node types
        self.INTERFACE_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#4285f4',
            'color': '#2962ff',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.NETWORK_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#34a853',
            'color': '#1b5e20',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.POLICY_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#ea4335',
            'color': '#c62828',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.ROUTE_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#fbbc05',
            'color': '#f9a825',
            'fontcolor': 'black',
            'penwidth': '1.5'
        }
        
        self.VIP_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#ab47bc',
            'color': '#7b1fa2',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.ZONE_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#00acc1',
            'color': '#006064',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.GROUP_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#ff7043',
            'color': '#e64a19',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.SERVICE_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#5c6bc0',
            'color': '#3949ab',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.POOL_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#78909c',
            'color': '#455a64',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.SD_WAN_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#7cb342',
            'color': '#558b2f',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }
        
        self.VPN_STYLE = {
            'shape': 'rectangle',
            'style': 'filled,rounded',
            'fillcolor': '#26a69a',
            'color': '#00796b',
            'fontcolor': 'white',
            'penwidth': '1.5'
        }

    def _add_node(self, name, **attrs):
        """Add a node with specified attributes and modern styling."""
        if name not in self.processed_nodes:
            # Add default modern styling with reduced complexity
            default_attrs = {
                'fontname': 'Helvetica',
                'fontsize': '9',
                'margin': '0.2',
                'height': '0.4',
                'width': '0.8',
                'penwidth': '1.0'
            }
            # Merge default attributes with provided attributes
            attrs = {**default_attrs, **attrs}
            self.graph.node(name, **attrs)
            self.processed_nodes.add(name)

    def _add_edge(self, src, dst, **attrs):
        """Add an edge with specified attributes and modern styling."""
        # Default modern edge styling with reduced complexity
        default_attrs = {
            'fontname': 'Helvetica',
            'fontsize': '8',
            'penwidth': '0.8',
            'color': '#666666',
            'arrowsize': '0.6',
            'weight': '1'
        }
        # Convert regular labels to xlabel for better compatibility
        if 'label' in attrs:
            attrs['xlabel'] = attrs.pop('label')
        # Merge default attributes with provided attributes
        attrs = {**default_attrs, **attrs}
        self.graph.edge(src, dst, **attrs)

    def _get_subnet_label(self, subnet):
        """Format subnet for display."""
        if not subnet:
            return "N/A"
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            return f"{net.network_address}/{net.prefixlen}"
        except ValueError:
            return subnet

    def _expand_address_group(self, group_name):
        """Recursively expand address group members."""
        if group_name in self.address_groups_expanded:
            return self.address_groups_expanded[group_name]
            
        members = set()
        if group_name in self.model.addr_groups:
            for member in self.model.addr_groups[group_name]:
                if member in self.model.addresses:
                    members.add(member)
                elif member in self.model.addr_groups:
                    members.update(self._expand_address_group(member))
                    
        self.address_groups_expanded[group_name] = members
        return members

    def _expand_service_group(self, group_name):
        """Recursively expand service group members."""
        if group_name in self.service_groups_expanded:
            return self.service_groups_expanded[group_name]
            
        members = set()
        if group_name in self.model.svc_groups:
            for member in self.model.svc_groups[group_name]:
                if member in self.model.services:
                    members.add(member)
                elif member in self.model.svc_groups:
                    members.update(self._expand_service_group(member))
                    
        self.service_groups_expanded[group_name] = members
        return members

    def generate_zones(self):
        """Add zones and their interface relationships."""
        for name, interfaces in self.model.zones.items():
            zone_label = [f"Zone: {name}"]
            if interfaces:
                zone_label.append(f"Interfaces: {', '.join(interfaces)}")
            with self.graph.subgraph(name='cluster_zones') as zones:
                zones.attr(label='\\n'.join(zone_label))
                zones.attr(style='rounded,filled')
                zones.attr(fillcolor='white')
                zones.attr(color='gray70')
                zones.attr(fontname='Arial Bold')
                for iface in interfaces:
                    self._add_edge(f"iface_{iface}", f"zone_{name}")

    def generate_address_objects(self):
        """Add address objects and groups to the diagram."""
        # Add individual addresses
        for name, addr in self.model.addresses.items():
            label = [f"Address: {name}"]
            if 'type' in addr:
                label.append(f"Type: {addr['type']}")
            if 'subnet' in addr:
                label.append(f"Subnet: {self._get_subnet_label(addr['subnet'])}")
            if 'comment' in addr and addr['comment']:
                label.append(f"Comment: {addr['comment']}")
                
            with self.graph.subgraph(name='cluster_addresses') as addr:
                addr.attr(label='\\n'.join(label))
                addr.attr(style='rounded,filled')
                addr.attr(fillcolor='white')
                addr.attr(color='gray70')
                self._add_node(f"addr_{name}", **self.NETWORK_STYLE)
        
        # Add address groups
        for name, members in self.model.addr_groups.items():
            expanded_members = self._expand_address_group(name)
            label = [f"Address Group: {name}",
                    f"Members: {len(expanded_members)}"]
            with self.graph.subgraph(name='cluster_addrgrp') as addrgrp:
                addrgrp.attr(label='\\n'.join(label))
                addrgrp.attr(style='rounded,filled')
                addrgrp.attr(fillcolor='white')
                addrgrp.attr(color='gray70')
                self._add_node(f"addrgrp_{name}", **self.GROUP_STYLE)
                
                # Connect group to its immediate members
                for member in members:
                    if member in self.model.addresses:
                        self._add_edge(f"addrgrp_{name}", f"addr_{member}")
                    elif member in self.model.addr_groups:
                        self._add_edge(f"addrgrp_{name}", f"addrgrp_{member}")

    def generate_services(self):
        """Add services and service groups to the diagram."""
        # Add individual services
        for name, svc in self.model.services.items():
            label = [f"Service: {name}"]
            if 'protocol' in svc:
                label.append(f"Protocol: {svc['protocol']}")
            if 'port' in svc:
                label.append(f"Port: {svc['port']}")
            if 'comment' in svc and svc['comment']:
                label.append(f"Comment: {svc['comment']}")
                
            with self.graph.subgraph(name='cluster_services') as svc:
                svc.attr(label='\\n'.join(label))
                svc.attr(style='rounded,filled')
                svc.attr(fillcolor='white')
                svc.attr(color='gray70')
                self._add_node(f"svc_{name}", **self.SERVICE_STYLE)
        
        # Add service groups
        for name, members in self.model.svc_groups.items():
            expanded_members = self._expand_service_group(name)
            label = [f"Service Group: {name}",
                    f"Members: {len(expanded_members)}"]
            with self.graph.subgraph(name='cluster_svcgrp') as svcgrp:
                svcgrp.attr(label='\\n'.join(label))
                svcgrp.attr(style='rounded,filled')
                svcgrp.attr(fillcolor='white')
                svcgrp.attr(color='gray70')
                self._add_node(f"svcgrp_{name}", **self.GROUP_STYLE)
                
                # Connect group to its immediate members
                for member in members:
                    if member in self.model.services:
                        self._add_edge(f"svcgrp_{name}", f"svc_{member}")
                    elif member in self.model.svc_groups:
                        self._add_edge(f"svcgrp_{name}", f"svcgrp_{member}")

    def generate_routes(self):
        """Add static routes to the diagram."""
        for route in self.model.routes:
            route_name = route.get('name', '')
            dst = self._get_subnet_label(route.get('dst', ''))
            gw = route.get('gateway', '')
            device = route.get('device', '')
            distance = route.get('distance', '')
            
            label = [f"Route: {route_name}"]
            if dst:
                label.append(f"Destination: {dst}")
            if gw:
                label.append(f"Gateway: {gw}")
            if distance:
                label.append(f"Distance: {distance}")
            if route.get('comment'):
                label.append(f"Comment: {route['comment']}")
                
            with self.graph.subgraph(name='cluster_route') as route:
                route.attr(label='\\n'.join(label))
                route.attr(style='rounded,filled')
                route.attr(fillcolor='white')
                route.attr(color='gray70')
                self._add_node(f"route_{route_name}", **self.ROUTE_STYLE)
                
                # Connect route to interface
                if device:
                    self._add_edge(f"route_{route_name}", f"iface_{device}")

    def generate_vips(self):
        """Add virtual IPs to the diagram."""
        for name, vip in self.model.vips.items():
            label = [f"VIP: {name}"]
            if 'extip' in vip:
                label.append(f"External IP: {vip['extip']}")
            if 'mappedip' in vip:
                label.append(f"Mapped IP: {vip['mappedip']}")
            if 'portforward' in vip:
                label.append(f"Port Forward: {vip['portforward']}")
            if 'protocol' in vip:
                label.append(f"Protocol: {vip['protocol']}")
                
            with self.graph.subgraph(name='cluster_vip') as vip:
                vip.attr(label='\\n'.join(label))
                vip.attr(style='rounded,filled')
                vip.attr(fillcolor='white')
                vip.attr(color='gray70')
                self._add_node(f"vip_{name}", **self.VIP_STYLE)
                
                # Connect VIP to relevant interface if specified
                if 'interface' in vip:
                    self._add_edge(f"iface_{vip['interface']}", f"vip_{name}")

    def generate_ip_pools(self):
        """Add IP pools to the diagram."""
        if self.model.ippools:
            with self.graph.subgraph(name='cluster_ippools') as c:
                c.attr(label='IP Pools')
                for name, pool in self.model.ippools.items():
                    label = [f"Pool: {name}"]
                    if 'startip' in pool and 'endip' in pool:
                        label.append(f"Range: {pool['startip']}-{pool['endip']}")
                    if 'type' in pool:
                        label.append(f"Type: {pool['type']}")
                    if 'comment' in pool and pool['comment']:
                        label.append(f"Comment: {pool['comment']}")
                        
                    with self.graph.subgraph(name='cluster_pool') as pool:
                        pool.attr(label='\\n'.join(label))
                        pool.attr(style='rounded,filled')
                        pool.attr(fillcolor='white')
                        pool.attr(color='gray70')
                        self._add_node(f"pool_{name}", **self.POOL_STYLE)

    def _create_cluster(self, name, label):
        """Helper method to create a cluster with consistent modern styling."""
        cluster = self.graph.subgraph(name=f'cluster_{name}')
        # Apply the default cluster styling
        for key, value in self.CLUSTER_STYLE.items():
            cluster.attr(**{key: value})
        cluster.attr(label=label)
        return cluster

    def _create_subgraph(self, parent, name, label):
        """Helper method to create a subgraph within a parent graph."""
        subgraph = parent.subgraph(name=f'cluster_{name}')
        # Apply the default cluster styling
        for key, value in self.CLUSTER_STYLE.items():
            subgraph.attr(**{key: value})
        subgraph.attr(label=label)
        return subgraph

    def generate_network_hierarchy(self):
        """Generate the complete network hierarchy with improved layout."""
        # Network topology section
        self.graph.attr(label='Network Topology')
        
        # Create zones section
        with self.graph.subgraph(name='cluster_zones') as zones:
            zones.attr(**self.CLUSTER_STYLE)
            zones.attr(label='Security Zones')
            self.generate_zones()
        
        # Create interfaces section
        with self.graph.subgraph(name='cluster_interfaces') as interfaces:
            interfaces.attr(**self.CLUSTER_STYLE)
            interfaces.attr(label='Network Interfaces')
            self.generate_interfaces()
        
        # Create routing section
        with self.graph.subgraph(name='cluster_routing') as routing:
            routing.attr(**self.CLUSTER_STYLE)
            routing.attr(label='Routing')
            
            # Static routes subsection
            with routing.subgraph(name='cluster_static_routes') as static_routes:
                static_routes.attr(**self.CLUSTER_STYLE)
                static_routes.attr(label='Static Routes')
                self.generate_routes()
            
            # SD-WAN subsection
            with routing.subgraph(name='cluster_sdwan') as sdwan:
                sdwan.attr(**self.CLUSTER_STYLE)
                sdwan.attr(label='SD-WAN')
                self.generate_sd_wan()
        
        # Create VPN section
        with self.graph.subgraph(name='cluster_vpn') as vpn:
            vpn.attr(**self.CLUSTER_STYLE)
            vpn.attr(label='VPN Configuration')
            self.generate_vpn_tunnels()

    def generate_security_configuration(self):
        """Generate the security-related configuration with improved layout."""
        with self.graph.subgraph(name='cluster_security') as security:
            security.attr(**self.CLUSTER_STYLE)
            security.attr(label='Security Configuration')
            
            # Create address objects section
            with security.subgraph(name='cluster_addresses') as addresses:
                addresses.attr(**self.CLUSTER_STYLE)
                addresses.attr(label='Address Objects')
                self.generate_address_objects()
            
            # Create services section
            with security.subgraph(name='cluster_services') as services:
                services.attr(**self.CLUSTER_STYLE)
                services.attr(label='Services')
                self.generate_services()
            
            # Create policies section
            with security.subgraph(name='cluster_policies') as policies:
                policies.attr(**self.CLUSTER_STYLE)
                policies.attr(label='Security Policies')
                self.generate_policies()

    def generate_nat_configuration(self):
        """Generate NAT-related configuration with improved layout."""
        with self.graph.subgraph(name='cluster_nat') as nat:
            nat.attr(**self.CLUSTER_STYLE)
            nat.attr(label='NAT Configuration')
            
            # Create VIPs section
            with nat.subgraph(name='cluster_vips') as vips:
                vips.attr(**self.CLUSTER_STYLE)
                vips.attr(label='Virtual IPs')
                self.generate_vips()
            
            # Create IP Pools section
            with nat.subgraph(name='cluster_pools') as pools:
                pools.attr(**self.CLUSTER_STYLE)
                pools.attr(label='IP Pools')
                self.generate_ip_pools()

    def generate_sd_wan(self):
        """Generate SD-WAN configuration if present."""
        if hasattr(self.model, 'sd_wan') and self.model.sd_wan:
            sd_wan_config = self.model.sd_wan
            label = ['SD-WAN']
            
            if 'status' in sd_wan_config:
                label.append(f"Status: {sd_wan_config['status']}")
            if 'load-balance-mode' in sd_wan_config:
                label.append(f"Mode: {sd_wan_config['load-balance-mode']}")
                
            with self.graph.subgraph(name='cluster_sdwan') as sdwan:
                sdwan.attr(label='\\n'.join(label))
                sdwan.attr(style='rounded,filled')
                sdwan.attr(fillcolor='white')
                sdwan.attr(color='gray70')
                # Connect SD-WAN to member interfaces
                if 'members' in sd_wan_config:
                    for member in sd_wan_config['members']:
                        if member in self.model.interfaces:
                            self._add_edge('sd_wan', f"iface_{member}")

    def generate_vpn_tunnels(self):
        """Generate VPN tunnel configuration."""
        # IPsec VPN Phase 1
        for name, phase1 in self.model.phase1.items():
            label = [f"VPN: {name}"]
            if 'interface' in phase1:
                label.append(f"Interface: {phase1['interface']}")
            if 'remote-gw' in phase1:
                label.append(f"Remote GW: {phase1['remote-gw']}")
                
            with self.graph.subgraph(name='cluster_vpn') as vpn:
                vpn.attr(label='\\n'.join(label))
                vpn.attr(style='rounded,filled')
                vpn.attr(fillcolor='white')
                vpn.attr(color='gray70')
                # Connect VPN to interface
                if 'interface' in phase1:
                    self._add_edge(f"vpn_{name}", f"iface_{phase1['interface']}")
                
                # Add Phase 2 configurations
                if name in self.model.phase2:
                    phase2 = self.model.phase2[name]
                    if 'src-subnet' in phase2:
                        self._add_edge(f"vpn_{name}", 
                                     f"net_vpn_{name}_local",
                                     label="Local Subnet")
                    if 'dst-subnet' in phase2:
                        self._add_edge(f"vpn_{name}",
                                     f"net_vpn_{name}_remote",
                                     label="Remote Subnet")

    def generate_interfaces(self):
        """Add interfaces to the diagram with enhanced details."""
        for name, iface in self.model.interfaces.items():
            # Create detailed interface label
            label_parts = [f"Interface: {name}"]
            
            # Add IP information
            if 'ip' in iface:
                label_parts.append(f"IP: {iface['ip']}")
            
            # Add interface type
            if 'type' in iface:
                label_parts.append(f"Type: {iface['type']}")
            
            # Add allowed access methods
            if 'allowaccess' in iface:
                label_parts.append(f"Access: {','.join(iface['allowaccess'])}")
            
            # Add status if available
            if 'status' in iface:
                label_parts.append(f"Status: {iface['status']}")
            
            # Add role if defined
            if 'role' in iface:
                label_parts.append(f"Role: {iface['role']}")
            
            # Add VDOM if applicable
            if 'vdom' in iface:
                label_parts.append(f"VDOM: {iface['vdom']}")
            
            with self.graph.subgraph(name='cluster_iface') as iface:
                iface.attr(label='\\n'.join(label_parts))
                iface.attr(style='rounded,filled')
                iface.attr(fillcolor='white')
                iface.attr(color='gray70')
                self._add_node(f"iface_{name}", **self.INTERFACE_STYLE)
                
                # Add VLAN information if applicable
                if name in self.model.vlans:
                    vlan = self.model.vlans[name]
                    vlan_label_parts = [
                        f"VLAN: {name}",
                        f"ID: {vlan.get('vlanid', '')}",
                        f"Members: {','.join(vlan.get('members', []))}"
                    ]
                    with self.graph.subgraph(name='cluster_vlan') as vlan:
                        vlan.attr(label='\\n'.join(vlan_label_parts))
                        vlan.attr(style='rounded,filled')
                        vlan.attr(fillcolor='white')
                        vlan.attr(color='gray70')
                        self._add_node(f"vlan_{name}", shape='tab', color='blue')
                        self._add_edge(f"vlan_{name}", f"iface_{name}")

    def generate_policies(self):
        """Add firewall policies with enhanced relationship mapping."""
        with self.graph.subgraph(name='cluster_policies') as policies:
            policies.attr(**self.CLUSTER_STYLE)
            policies.attr(label='Security Policies')
            
            for policy in self.model.policies:
                policy_id = policy.get('id', '')
                
                # Create detailed policy label
                label_parts = [f"Policy {policy_id}"]
                label_parts.append(f"Action: {policy.get('action', '')}")
                
                if policy.get('nat', ''):
                    label_parts.append("NAT: Enabled")
                
                label_parts.append(f"Status: {policy.get('status', '')}")
                
                if 'schedule' in policy:
                    label_parts.append(f"Schedule: {policy['schedule']}")
                
                if 'comments' in policy:
                    label_parts.append(f"Comments: {policy['comments']}")
                
                # Add policy node
                self._add_node(f"policy_{policy_id}", 
                             label='\\n'.join(label_parts),
                             **self.POLICY_STYLE)
                
                # Connect policy elements
                self._connect_policy_elements(policy, 'src', policy_id)
                self._connect_policy_elements(policy, 'dst', policy_id)
                self._connect_policy_services(policy, policy_id)

    def _connect_policy_elements(self, policy_data, direction, policy_id):
        """Helper method to connect policy elements (source or destination)."""
        intf_key = f"{direction}intf"
        addr_key = f"{direction}addr"
        
        # Connect interfaces/zones
        for intf in policy_data.get(intf_key, []):
            if intf in self.model.zones:
                if direction == 'src':
                    self._add_edge(f"zone_{intf}", f"policy_{policy_id}")
                else:
                    self._add_edge(f"policy_{policy_id}", f"zone_{intf}")
            else:
                if direction == 'src':
                    self._add_edge(f"iface_{intf}", f"policy_{policy_id}")
                else:
                    self._add_edge(f"policy_{policy_id}", f"iface_{intf}")
        
        # Connect addresses/groups
        for addr in policy_data.get(addr_key, []):
            if addr in self.model.addresses:
                if direction == 'src':
                    self._add_edge(f"addr_{addr}", f"policy_{policy_id}")
                else:
                    self._add_edge(f"policy_{policy_id}", f"addr_{addr}")
            elif addr in self.model.addr_groups:
                if direction == 'src':
                    self._add_edge(f"addrgrp_{addr}", f"policy_{policy_id}")
                else:
                    self._add_edge(f"policy_{policy_id}", f"addrgrp_{addr}")

    def _connect_policy_services(self, policy_data, policy_id):
        """Helper method to connect policy services."""
        for service in policy_data.get('service', []):
            if service in self.model.services:
                self._add_edge(f"svc_{service}", f"policy_{policy_id}")
            elif service in self.model.svc_groups:
                self._add_edge(f"svcgrp_{service}", f"policy_{policy_id}")

    def analyze_relationships(self):
        """Analyze and collect statistics about object relationships."""
        # Analyze zone-interface relationships
        for zone, interfaces in self.model.zones.items():
            self.relationship_stats['zone_interface_count'][zone] = len(interfaces)
        
        # Analyze policy relationships
        for policy in self.model.policies:
            policy_id = policy.get('id', '')
            self.relationship_stats['policy_address_count'][policy_id] = {
                'src': len(policy.get('srcaddr', [])),
                'dst': len(policy.get('dstaddr', []))
            }
            self.relationship_stats['policy_service_count'][policy_id] = len(policy.get('service', []))
        
        # Analyze interface policy usage
        for policy in self.model.policies:
            for intf in policy.get('srcintf', []) + policy.get('dstintf', []):
                self.relationship_stats['interface_policy_count'][intf] = \
                    self.relationship_stats['interface_policy_count'].get(intf, 0) + 1
        
        # Analyze address and service usage in policies
        for policy in self.model.policies:
            for addr in policy.get('srcaddr', []) + policy.get('dstaddr', []):
                self.relationship_stats['address_policy_count'][addr] = \
                    self.relationship_stats['address_policy_count'].get(addr, 0) + 1
            for svc in policy.get('service', []):
                self.relationship_stats['service_policy_count'][svc] = \
                    self.relationship_stats['service_policy_count'].get(svc, 0) + 1
        
        # Analyze group nesting depth
        self._analyze_group_depth('address')
        self._analyze_group_depth('service')
    
    def _analyze_group_depth(self, group_type):
        """Analyze the nesting depth of address or service groups."""
        def calculate_depth(name, visited=None):
            if visited is None:
                visited = set()
            if name in visited:
                return 0  # Prevent infinite recursion
            visited.add(name)
            
            if group_type == 'address':
                if name not in self.model.addr_groups:
                    return 0
                members = self.model.addr_groups[name]
            else:  # service
                if name not in self.model.svc_groups:
                    return 0
                members = self.model.svc_groups[name]
            
            max_depth = 0
            for member in members:
                depth = calculate_depth(member, visited.copy())
                max_depth = max(max_depth, depth)
            return max_depth + 1
        
        # Calculate depth for each group
        if group_type == 'address':
            for group in self.model.addr_groups:
                self.relationship_stats['address_group_depth'][group] = calculate_depth(group)
        else:
            for group in self.model.svc_groups:
                self.relationship_stats['service_group_depth'][group] = calculate_depth(group)
    
    def generate_relationship_summary(self):
        """Generate a detailed summary of object relationships."""
        summary = []
        
        # Zone Analysis
        summary.append("=== Zone Relationship Analysis ===")
        for zone, count in self.relationship_stats['zone_interface_count'].items():
            summary.append(f"Zone '{zone}' contains {count} interfaces")
            interfaces = self.model.zones[zone]
            summary.append(f"  Interfaces: {', '.join(interfaces)}")
        
        # Policy Analysis
        summary.append("\n=== Policy Relationship Analysis ===")
        for policy_id, counts in self.relationship_stats['policy_address_count'].items():
            summary.append(f"\nPolicy {policy_id}:")
            summary.append(f"  Source Addresses: {counts['src']}")
            summary.append(f"  Destination Addresses: {counts['dst']}")
            summary.append(f"  Services: {self.relationship_stats['policy_service_count'][policy_id]}")
        
        # Interface Usage Analysis
        summary.append("\n=== Interface Usage Analysis ===")
        for intf, count in self.relationship_stats['interface_policy_count'].items():
            summary.append(f"Interface '{intf}' is used in {count} policies")
        
        # Address Usage Analysis
        summary.append("\n=== Address Usage Analysis ===")
        for addr, count in self.relationship_stats['address_policy_count'].items():
            summary.append(f"Address '{addr}' is used in {count} policies")
        
        # Service Usage Analysis
        summary.append("\n=== Service Usage Analysis ===")
        for svc, count in self.relationship_stats['service_policy_count'].items():
            summary.append(f"Service '{svc}' is used in {count} policies")
        
        # Group Nesting Analysis
        summary.append("\n=== Group Nesting Analysis ===")
        summary.append("Address Groups:")
        for group, depth in self.relationship_stats['address_group_depth'].items():
            summary.append(f"  {group}: Nesting Depth = {depth}")
        summary.append("\nService Groups:")
        for group, depth in self.relationship_stats['service_group_depth'].items():
            summary.append(f"  {group}: Nesting Depth = {depth}")
        
        return '\n'.join(summary)
    
    def generate_diagram(self, output_file='network_topology'):
        """Generate the complete network diagram with improved organization and modern styling."""
        try:
            # Analyze relationships before generating the diagram
            self.analyze_relationships()
            
            # Generate main configuration sections
            self.generate_network_hierarchy()
            self.generate_security_configuration()
            self.generate_nat_configuration()
            
            # Generate relationship summary
            summary = self.generate_relationship_summary()
            summary_file = f"{output_file}_relationships.txt"
            with open(summary_file, 'w') as f:
                f.write(summary)
            
            # Set rendering options based on graph complexity
            num_nodes = len(self.processed_nodes)
            
            # Adjust graph attributes based on size
            if num_nodes > 100:
                self.graph.attr(
                    dpi='96',
                    size='14,20',
                    nodesep='0.3',
                    ranksep='0.4',
                    fontsize='8'
                )
            elif num_nodes > 50:
                self.graph.attr(
                    dpi='120',
                    size='11,16',
                    nodesep='0.4',
                    ranksep='0.5',
                    fontsize='9'
                )
            else:
                self.graph.attr(
                    dpi='150',
                    size='8.5,11',
                    nodesep='0.5',
                    ranksep='0.6',
                    fontsize='10'
                )
            
            # Try different layout engines if dot fails
            engines = ['dot', 'fdp', 'neato']
            success = False
            
            for engine in engines:
                try:
                    self.graph.engine = engine
                    # Generate PDF
                    self.graph.render(output_file, view=False, format='pdf', cleanup=True)
                    # Generate PNG with web-friendly settings
                    self.graph.attr(dpi='144')
                    self.graph.render(output_file, view=False, format='png', cleanup=True)
                    success = True
                    break
                except Exception as e:
                    print(f"Engine {engine} failed: {str(e)}")
                    continue
            
            if not success:
                raise Exception("All layout engines failed")
            
            print(f"\nNetwork diagrams have been generated with modern styling:")
            print(f"- {output_file}.pdf (High-quality vector format)")
            print(f"- {output_file}.png (Web-optimized format)")
            print(f"- {summary_file} (Detailed relationship analysis)")
            print(f"\nDiagram contains {num_nodes} nodes with modern styling and layout.")
            print(f"Used layout engine: {engine}")
            
        except Exception as e:
            print(f"Error generating diagram: {e}")
            print("Please ensure Graphviz is installed on your system and has sufficient memory.")
            print("You may also try reducing the complexity of the diagram or updating Graphviz.")

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
        return ep

class FortiParser:
    """Parses a FortiGate CLI export into a ConfigModel."""
    SECTION_RE = re.compile(r'^config\s+(.+)$')
    EDIT_RE    = re.compile(r'^edit\s+"?([^"]+?)"?$')
    SET_RE     = re.compile(r'^set\s+(\S+)\s+(.+)$')
    NEXT_RE    = re.compile(r'^next$')
    END_RE     = re.compile(r'^end$')

    def __init__(self, lines):
        self.lines = lines
        self.i     = 0
        self.model = ConfigModel()

    def parse(self):
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            m = self.SECTION_RE.match(line)
            if m:
                sec_raw = m.group(1).lower()
                sec = sec_raw.replace(' ', '_').replace('-', '_')
                handler = getattr(self, f"_handle_{sec}", None)
                if handler:
                    handler()
                else:
                    self._skip_block()
            else:
                self.i += 1

        # post‑process policies
        self.model.policies = [self.model.expand_policy(p) for p in self.model.policies]
        return self.model

    def _skip_block(self):
        depth = 1
        self.i += 1
        while self.i < len(self.lines) and depth:
            l = self.lines[self.i].strip()
            if l.startswith('config '):
                depth += 1
            elif self.END_RE.match(l):
                depth -= 1
            self.i += 1

    def _read_block(self):
        entry = {}
        # find 'edit'
        while self.i < len(self.lines):
            l = self.lines[self.i].strip()
            m = self.EDIT_RE.match(l)
            if m:
                entry['name'] = m.group(1)
                self.i += 1
                break
            if self.END_RE.match(l):
                return None
            self.i += 1

        # read until 'next'
        while self.i < len(self.lines):
            l = self.lines[self.i].strip()
            if self.NEXT_RE.match(l):
                self.i += 1
                break
            if l.startswith('config '):
                self._skip_block()
                continue
            m = self.SET_RE.match(l)
            if m:
                k, v = m.group(1), m.group(2).strip().strip('"')
                entry[k] = v
            self.i += 1

        return entry

    def _read_settings(self):
        cfg = {}
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            l = self.lines[self.i].strip()
            m = self.SET_RE.match(l)
            if m:
                k, v = m.group(1), m.group(2).strip().strip('"')
                cfg[k] = v
            self.i += 1
        self.i += 1
        return cfg

    # --- section handlers ---

    def _handle_router_static(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                status = blk.get('status', 'enable')
                self.model.routes.append({
                    'name':     blk.get('name',''),
                    'dst':      blk.get('dst',''),
                    'gateway':  blk.get('gateway',''),
                    'device':   blk.get('device',''),
                    'distance': blk.get('distance',''),
                    'comment':  blk.get('comment',''),
                    'status':   status
                })
        self.i += 1

    def _handle_firewall_address(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                subnet = blk.get('subnet') or f"{blk.get('start-ip')}/{blk.get('end-ip','')}".rstrip('/')
                self.model.addresses[blk['name']] = {
                    'type':   blk.get('type','subnet'),
                    'subnet': subnet,
                    'comment': blk.get('comment','')
                }
        self.i += 1

    def _handle_firewall_addrgrp(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.addr_groups[blk['name']] = blk.get('member','').split()
        self.i += 1

    def _handle_firewall_service_custom(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                port = blk.get('tcp-portrange') or blk.get('udp-portrange','')
                self.model.services[blk['name']] = {
                    'protocol': blk.get('protocol',''),
                    'port':     port,
                    'comment':  blk.get('comment','')
                }
        self.i += 1

    def _handle_firewall_service_group(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.svc_groups[blk['name']] = blk.get('member','').split()
        self.i += 1

    def _handle_firewall_policy(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                for fld in ('srcintf','dstintf','srcaddr','dstaddr','service'):
                    if fld in blk:
                        blk[fld] = blk[fld].split()
                self.model.policies.append({
                    'id':       blk.get('name',''),
                    'srcintf':  blk.get('srcintf',[]),
                    'dstintf':  blk.get('dstintf',[]),
                    'srcaddr':  blk.get('srcaddr',[]),
                    'dstaddr':  blk.get('dstaddr',[]),
                    'service':  blk.get('service',[]),
                    'action':   blk.get('action',''),
                    'nat':      blk.get('nat',''),
                    'status':   blk.get('status',''),
                    'comments': blk.get('comments','')
                })
        self.i += 1

    def _handle_system_interface(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.interfaces[blk['name']] = {
                    'ip':          blk.get('ip',''),
                    'type':        blk.get('type',''),
                    'allowaccess': blk.get('allowaccess','').split(),
                    'role':        blk.get('role',''),
                    'vdom':        blk.get('vdom',''),
                    'alias':       blk.get('alias','')
                }
        self.i += 1

    def _handle_switch_vlan(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.vlans[blk['name']] = {
                    'vlanid':    blk.get('vlanid',''),
                    'interface': blk.get('interface',''),
                    'members':   blk.get('member','').split()
                }
        self.i += 1

    def _handle_system_zone(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.zones[blk['name']] = blk.get('interface','').split()
        self.i += 1

    def _handle_firewall_vip(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.vips[name] = blk
        self.i += 1

    def _handle_firewall_vipgrp(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.vip_groups[blk['name']] = blk.get('member','').split()
        self.i += 1

    def _handle_firewall_ippool(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.ippools[blk['name']] = {
                    'startip': blk.get('startip') or blk.get('start-ip',''),
                    'endip':   blk.get('endip')   or blk.get('end-ip',''),
                    'type':    blk.get('type',''),
                    'comment': blk.get('comment','')
                }
        self.i += 1

    def _handle_system_dhcp_server(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.dhcp_servers.append(blk)
        self.i += 1

    def _handle_router_ospf(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                nets = [v for k,v in blk.items() if k == 'network']
                self.model.ospf[blk['name']] = {
                    'router_id': blk.get('router-id',''),
                    'networks':  nets
                }
        self.i += 1

    def _handle_router_bgp(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.bgp[blk['name']] = {
                    'as':        blk.get('as',''),
                    'router_id': blk.get('router-id','')
                }
        self.i += 1

    def _handle_vpn_ipsec_phase1_interface(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.phase1[name] = blk
        self.i += 1

    def _handle_vpn_ipsec_phase2_interface(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.phase2[name] = blk
        self.i += 1

    def _handle_firewall_shaper_traffic_shaper(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.traffic_shapers[name] = blk
        self.i += 1

    def _handle_firewall_shaper_per_ip(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.shaper_per_ip[name] = blk
        self.i += 1

    def _handle_firewall_dos_policy(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.dos_policies.append(blk)
        self.i += 1

    def _handle_system_snmp_sysinfo(self):
        self.model.snmp_sysinfo = self._read_settings()

    def _handle_system_snmp_community(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.snmp_communities[name] = blk
        self.i += 1

    def _handle_user_ldap(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.ldap_servers[name] = blk
        self.i += 1

    def _handle_system_admin(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.admins[name] = blk
        self.i += 1

    def _handle_system_ha(self):
        self.model.ha = self._read_settings()

    def _handle_system_ntp(self):
        self.model.ntp = self._read_settings()

    def _handle_system_dns(self):
        self.model.dns = self._read_settings()

    def _handle_vpn_ssl_settings(self):
        self.model.ssl_settings = self._read_settings()

    def _handle_vpn_ssl_web_portal(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.ssl_portals[name] = blk
        self.i += 1

    def _handle_vpn_ssl_web_policy(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                self.model.ssl_policies.append(blk)
        self.i += 1

    def _handle_vrrp_interface(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.vrrp[name] = blk
        self.i += 1

    def _handle_system_global(self):
        self.model.system_global = self._read_settings()

    def _handle_antivirus_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.antivirus[name] = blk
        self.i += 1

    def _handle_ips_sensor(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.ips[name] = blk
        self.i += 1

    def _handle_webfilter_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.web_filter[name] = blk
        self.i += 1

    def _handle_application_list(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.app_control[name] = blk
        self.i += 1

    def _handle_ssl_ssh_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.ssl_inspection[name] = blk
        self.i += 1

    def _handle_waf_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.waf[name] = blk
        self.i += 1

    def _handle_emailfilter_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.email_filter[name] = blk
        self.i += 1

    def _handle_dlp_sensor(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.dlp[name] = blk
        self.i += 1

    def _handle_voip_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.voip[name] = blk
        self.i += 1

    def _handle_icap_server(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.icap[name] = blk
        self.i += 1

    def _handle_gtp_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.gtp[name] = blk
        self.i += 1

    def _handle_user_radius(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.radius_servers[name] = blk
        self.i += 1

    def _handle_user_group(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.user_groups[name] = blk
        self.i += 1

    def _handle_firewall_schedule_group(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.schedule_groups[name] = blk
        self.i += 1

    def _handle_firewall_schedule_onetime(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.schedule_onetime[name] = blk
        self.i += 1

    def _handle_firewall_schedule_recurring(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.schedule_recurring[name] = blk
        self.i += 1

    def _handle_system_sniffer_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.sniffer_profile[name] = blk
        self.i += 1

    def _handle_wanopt_profile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.wan_opt[name] = blk
        self.i += 1

    def _handle_user_fortitoken(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.fortitoken[name] = blk
        self.i += 1

    def _handle_system_fortiguard(self):
        self.model.fortiguard = self._read_settings()

    def _handle_log_setting(self):
        self.model.log_settings = self._read_settings()

    def _handle_system_sdwan(self):
        self.model.sd_wan = self._read_settings()

    def _handle_firewall_ldb_monitor(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.load_balance[name] = blk
        self.i += 1

    def _handle_wireless_controller_setting(self):
        self.model.wireless_controller = self._read_settings()

    def _handle_switch_controller_global(self):
        self.model.switch_controller = self._read_settings()

    def _handle_system_fortisandbox(self):
        self.model.sandbox = self._read_settings()

    def _handle_system_certificate(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.certificate[name] = blk
        self.i += 1

    def _handle_user_saml(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.saml[name] = blk
        self.i += 1

    def _handle_user_fsso(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.fsso[name] = blk
        self.i += 1

    def _handle_system_automation_action(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.automation[name] = blk
        self.i += 1

    def _handle_system_sdn_connector(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.sdn_connector[name] = blk
        self.i += 1

    def _handle_extender_controller_extender(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.extender[name] = blk
        self.i += 1

    def _handle_vpn_l2tp(self):
        self.model.vpn_l2tp = self._read_settings()

    def _handle_vpn_pptp(self):
        self.model.vpn_pptp = self._read_settings()

    def _handle_vpn_ssl_client(self):
        self.model.vpn_ssl_client = self._read_settings()

    def _handle_system_replacemsg(self):
        self.model.system_replacemsg = self._read_settings()

    def _handle_system_accprofile(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_accprofile[name] = blk
        self.i += 1

    def _handle_system_api_user(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_api_user[name] = blk
        self.i += 1

    def _handle_system_sso_admin(self):
        self.model.system_sso_admin = self._read_settings()

    def _handle_system_password_policy(self):
        self.model.system_password_policy = self._read_settings()

    def _handle_system_interface_policy(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_interface_policy[name] = blk
        self.i += 1

    def _handle_system_csf(self):
        self.model.system_csf = self._read_settings()

    def _handle_system_central_management(self):
        self.model.system_central_mgmt = self._read_settings()

    def _handle_system_auto_update(self):
        self.model.system_auto_update = self._read_settings()

    def _handle_system_session_ttl(self):
        self.model.system_session_ttl = self._read_settings()

    def _handle_system_gre_tunnel(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_gre_tunnel[name] = blk
        self.i += 1

    def _handle_system_ddns(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_ddns[name] = blk
        self.i += 1

    def _handle_system_dns_database(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_dns_database[name] = blk
        self.i += 1

    def _handle_system_dns_server(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_dns_server[name] = blk
        self.i += 1

    def _handle_system_proxy_arp(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_proxy_arp[name] = blk
        self.i += 1

    def _handle_system_virtual_wire_pair(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_virtual_wire_pair[name] = blk
        self.i += 1

    def _handle_system_wccp(self):
        self.model.system_wccp = self._read_settings()

    def _handle_system_sit_tunnel(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_sit_tunnel[name] = blk
        self.i += 1

    def _handle_system_ipip_tunnel(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_ipip_tunnel[name] = blk
        self.i += 1

    def _handle_system_vxlan(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_vxlan[name] = blk
        self.i += 1

    def _handle_system_geneve(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_geneve[name] = blk
        self.i += 1

    def _handle_system_network_visibility(self):
        self.model.system_network_visibility = self._read_settings()

    def _handle_system_ptp(self):
        self.model.system_ptp = self._read_settings()

    def _handle_system_tos_based_priority(self):
        self.i += 1
        while not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk:
                name = blk.pop('name')
                self.model.system_tos_based_priority[name] = blk
        self.i += 1

    def _handle_system_email_server(self):
        self.model.system_email_server = self._read_settings()

    def _handle_system_dns_filter(self):
        self.model.system_dns_filter = self._read_settings()

    def _handle_system_ips_urlfilter_dns(self):
        self.model.system_ips_urlfilter_dns = self._read_settings()

    def _handle_system_fortiguard(self):
        self.model.system_fortiguard = self._read_settings()

    def _handle_system_fm(self):
        self.model.system_fm = self._read_settings()

    def _handle_system_fortianalyzer(self):
        self.model.system_fortianalyzer = self._read_settings()

    def _handle_system_fortisandbox(self):
        self.model.system_fortisandbox = self._read_settings()

def print_table(title, headers, rows):
    """Print an ASCII table given headers and rows of data."""
    cols = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    sep = '+' + '+'.join('-'*(w+2) for w in widths) + '+'
    print(f"\n{title}")
    print(sep)
    # header
    hrow = '|' + '|'.join(f' {headers[i].ljust(widths[i])} ' for i in range(cols)) + '|'
    print(hrow)
    print(sep)
    # rows
    for r in rows:
        row = '|' + '|'.join(f' {str(r[i]).ljust(widths[i])} ' for i in range(cols)) + '|'
        print(row)
    print(sep)

def main():
    p = argparse.ArgumentParser(description="FortiGate Comprehensive Table Parser")
    p.add_argument('config_file', help="FortiGate CLI export text file")
    args = p.parse_args()

    try:
        text = open(args.config_file, encoding='utf-8').read()
    except OSError as e:
        sys.stderr.write(f"Error opening {args.config_file}: {e}\n")
        sys.exit(1)

    model = FortiParser(text.splitlines()).parse()

    # Static Routes (with Type & Enabled)
    rows = []
    for r in model.routes:
        # determine if destination is CIDR or interface service
        if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', r['dst']):
            dest_type = 'subnet'
        else:
            dest_type = 'interface_service'
        enabled = 'No' if r['status'] == 'disable' else 'Yes'
        rows.append([
            r['name'], r['dst'], r['gateway'], r['device'],
            r['distance'], r['comment'], dest_type, enabled
        ])
    print_table(
        "Static Routes",
        ["Name","Destination","Gateway","Interface","Distance","Comment","Type","Enabled"],
        rows
    )

    # Address Objects
    rows = [[n, a['type'], a['subnet'], a['comment']]
            for n,a in model.addresses.items()]
    print_table("Address Objects", ["Name","Type","Subnet","Comment"], rows)

    # Address Groups
    rows = [[n, ','.join(m)] for n,m in model.addr_groups.items()]
    print_table("Address Groups", ["Name","Members"], rows)

    # Custom Services
    rows = [[n, s['protocol'], s['port'], s['comment']]
            for n,s in model.services.items()]
    print_table("Custom Services", ["Name","Protocol","Port","Comment"], rows)

    # Service Groups
    rows = [[n, ','.join(m)] for n,m in model.svc_groups.items()]
    print_table("Service Groups", ["Name","Members"], rows)

    # Interfaces
    rows = [[n, i['ip'], i['type'], ','.join(i['allowaccess']),
             i['role'], i['vdom'], i['alias']]
            for n,i in model.interfaces.items()]
    print_table("Interfaces", ["Name","IP","Type","Access","Role","VDOM","Alias"], rows)

    # VLANs
    rows = [[n, v['vlanid'], v['interface'], ','.join(v['members'])]
            for n,v in model.vlans.items()]
    print_table("VLANs", ["Name","VLAN ID","Interface","Members"], rows)

    # Zones
    rows = [[n, ','.join(i)] for n,i in model.zones.items()]
    print_table("Zones", ["Name","Interfaces"], rows)

    # Firewall Policies
    rows = [[p['id'], ','.join(p['srcintf']), ','.join(p['dstintf']),
             ','.join(p['src_subnets']), ','.join(p['dst_subnets']),
             ','.join(p['services_expanded']), p['action'], p['nat'],
             p['status'], p['comments']]
            for p in model.policies]
    print_table(
        "Firewall Policies",
        ["ID","SrcIntf","DstIntf","SrcSubs","DstSubs","Services","Action","NAT","Status","Comments"],
        rows
    )

    # Virtual IPs
    rows = [[n, v.get('extip',''), v.get('mappedip',''),
             v.get('mappedport',''), v.get('protocol',''), v.get('comment','')]
            for n,v in model.vips.items()]
    print_table("Virtual IPs", ["Name","ExtIP","MapIP","MapPort","Proto","Comment"], rows)

    # VIP Groups
    rows = [[n, ','.join(m)] for n,m in model.vip_groups.items()]
    print_table("VIP Groups", ["Name","Members"], rows)

    # IP Pools
    rows = [[n, p['startip'], p['endip'], p['type'], p['comment']]
            for n,p in model.ippools.items()]
    print_table("IP Pools", ["Name","StartIP","EndIP","Type","Comment"], rows)

    # DHCP Servers
    rows = [[d.get('name',''), d.get('interface',''), d.get('lease-time',''),
             d.get('default-gateway',''), d.get('netmask',''), d.get('ip-range','')]
            for d in model.dhcp_servers]
    print_table("DHCP Servers", ["Name","Interface","LeaseTime","Gateway","Netmask","IPRange"], rows)

    # OSPF Routers
    rows = [[n, o['router_id'], ';'.join(o['networks'])]
            for n,o in model.ospf.items()]
    print_table("OSPF Routers", ["Name","Router ID","Networks"], rows)

    # BGP Routers
    rows = [[n, b['as'], b['router_id']] for n,b in model.bgp.items()]
    print_table("BGP Routers", ["Name","AS","Router ID"], rows)

    # IPsec Phase1 Interfaces
    if model.phase1:
        keys = sorted({k for props in model.phase1.values() for k in props})
        rows = [[n] + [model.phase1[n].get(k,'') for k in keys] for n in model.phase1]
        print_table("IPsec Phase1 Interfaces", ["Name"]+keys, rows)

    # IPsec Phase2 Interfaces
    if model.phase2:
        keys = sorted({k for props in model.phase2.values() for k in props})
        rows = [[n] + [model.phase2[n].get(k,'') for k in keys] for n in model.phase2]
        print_table("IPsec Phase2 Interfaces", ["Name"]+keys, rows)

    # Traffic Shapers
    if model.traffic_shapers:
        keys = sorted({k for props in model.traffic_shapers.values() for k in props})
        rows = [[n] + [model.traffic_shapers[n].get(k,'') for k in keys]
                for n in model.traffic_shapers]
        print_table("Traffic Shapers", ["Name"]+keys, rows)

    # Per-IP Shapers
    if model.shaper_per_ip:
        keys = sorted({k for props in model.shaper_per_ip.values() for k in props})
        rows = [[n] + [model.shaper_per_ip[n].get(k,'') for k in keys]
                for n in model.shaper_per_ip]
        print_table("Per-IP Shapers", ["Name"]+keys, rows)

    # DoS Policies
    if model.dos_policies:
        keys = sorted({k for blk in model.dos_policies for k in blk if k!='name'})
        rows = [[blk.get('name','')] + [blk.get(k,'') for k in keys]
                for blk in model.dos_policies]
        print_table("DoS Policies", ["Name"]+keys, rows)

    # SNMP System Info
    if model.snmp_sysinfo:
        rows = [[k, v] for k,v in model.snmp_sysinfo.items()]
        print_table("SNMP System Info", ["Setting","Value"], rows)

    # SNMP Communities
    if model.snmp_communities:
        keys = sorted({k for props in model.snmp_communities.values() for k in props})
        rows = [[n] + [model.snmp_communities[n].get(k,'') for k in keys]
                for n in model.snmp_communities]
        print_table("SNMP Communities", ["Name"]+keys, rows)

    # LDAP Servers
    if model.ldap_servers:
        keys = sorted({k for props in model.ldap_servers.values() for k in props})
        rows = [[n] + [model.ldap_servers[n].get(k,'') for k in keys]
                for n in model.ldap_servers]
        print_table("LDAP Servers", ["Name"]+keys, rows)

    # Admin Accounts
    if model.admins:
        keys = sorted({k for props in model.admins.values() for k in props})
        rows = [[n] + [model.admins[n].get(k,'') for k in keys]
                for n in model.admins]
        print_table("Admin Accounts", ["Name"]+keys, rows)

    # High Availability Settings
    if model.ha:
        rows = [[k, v] for k,v in model.ha.items()]
        print_table("High Availability Settings", ["Setting","Value"], rows)

    # NTP Settings
    if model.ntp:
        rows = [[k, v] for k,v in model.ntp.items()]
        print_table("NTP Settings", ["Setting","Value"], rows)

    # DNS Settings
    if model.dns:
        rows = [[k, v] for k,v in model.dns.items()]
        print_table("DNS Settings", ["Setting","Value"], rows)

    # SSL VPN Global Settings
    if model.ssl_settings:
        rows = [[k, v] for k,v in model.ssl_settings.items()]
        print_table("SSL VPN Global Settings", ["Setting","Value"], rows)

    # SSL VPN Portals
    if model.ssl_portals:
        keys = sorted({k for props in model.ssl_portals.values() for k in props})
        rows = [[n] + [model.ssl_portals[n].get(k,'') for k in keys]
                for n in model.ssl_portals]
        print_table("SSL VPN Portals", ["Name"]+keys, rows)

    # SSL VPN Web Policies
    if model.ssl_policies:
        keys = sorted({k for blk in model.ssl_policies for k in blk if k!='name'})
        rows = [[blk.get('name','')] + [blk.get(k,'') for k in keys]
                for blk in model.ssl_policies]
        print_table("SSL VPN Web Policies", ["Name"]+keys, rows)

    # VRRP Interfaces
    if model.vrrp:
        keys = sorted({k for props in model.vrrp.values() for k in props})
        rows = [[n] + [model.vrrp[n].get(k,'') for k in keys]
                for n in model.vrrp]
        print_table("VRRP Interfaces", ["Name"]+keys, rows)

    # System Global Settings
    if model.system_global:
        rows = [[k, v] for k,v in model.system_global.items()]
        print_table("System Global Settings", ["Setting","Value"], rows)

    # Security Profiles
    # Antivirus Profiles
    if model.antivirus:
        keys = sorted({k for props in model.antivirus.values() for k in props})
        rows = [[n] + [model.antivirus[n].get(k,'') for k in keys]
                for n in model.antivirus]
        print_table("Antivirus Profiles", ["Name"]+keys, rows)

    # IPS Profiles
    if model.ips:
        keys = sorted({k for props in model.ips.values() for k in props})
        rows = [[n] + [model.ips[n].get(k,'') for k in keys]
                for n in model.ips]
        print_table("IPS Profiles", ["Name"]+keys, rows)

    # Web Filter Profiles
    if model.web_filter:
        keys = sorted({k for props in model.web_filter.values() for k in props})
        rows = [[n] + [model.web_filter[n].get(k,'') for k in keys]
                for n in model.web_filter]
        print_table("Web Filter Profiles", ["Name"]+keys, rows)

    # Application Control Profiles
    if model.app_control:
        keys = sorted({k for props in model.app_control.values() for k in props})
        rows = [[n] + [model.app_control[n].get(k,'') for k in keys]
                for n in model.app_control]
        print_table("Application Control Profiles", ["Name"]+keys, rows)

    # SSL/SSH Inspection Profiles
    if model.ssl_inspection:
        keys = sorted({k for props in model.ssl_inspection.values() for k in props})
        rows = [[n] + [model.ssl_inspection[n].get(k,'') for k in keys]
                for n in model.ssl_inspection]
        print_table("SSL/SSH Inspection Profiles", ["Name"]+keys, rows)

    # WAF Profiles
    if model.waf:
        keys = sorted({k for props in model.waf.values() for k in props})
        rows = [[n] + [model.waf[n].get(k,'') for k in keys]
                for n in model.waf]
        print_table("Web Application Firewall Profiles", ["Name"]+keys, rows)

    # Email Filter Profiles
    if model.email_filter:
        keys = sorted({k for props in model.email_filter.values() for k in props})
        rows = [[n] + [model.email_filter[n].get(k,'') for k in keys]
                for n in model.email_filter]
        print_table("Email Filter Profiles", ["Name"]+keys, rows)

    # DLP Profiles
    if model.dlp:
        keys = sorted({k for props in model.dlp.values() for k in props})
        rows = [[n] + [model.dlp[n].get(k,'') for k in keys]
                for n in model.dlp]
        print_table("Data Leak Prevention Profiles", ["Name"]+keys, rows)

    # VoIP Profiles
    if model.voip:
        keys = sorted({k for props in model.voip.values() for k in props})
        rows = [[n] + [model.voip[n].get(k,'') for k in keys]
                for n in model.voip]
        print_table("VoIP Profiles", ["Name"]+keys, rows)

    # ICAP Servers
    if model.icap:
        keys = sorted({k for props in model.icap.values() for k in props})
        rows = [[n] + [model.icap[n].get(k,'') for k in keys]
                for n in model.icap]
        print_table("ICAP Servers", ["Name"]+keys, rows)

    # GTP Profiles
    if model.gtp:
        keys = sorted({k for props in model.gtp.values() for k in props})
        rows = [[n] + [model.gtp[n].get(k,'') for k in keys]
                for n in model.gtp]
        print_table("GTP Profiles", ["Name"]+keys, rows)

    # RADIUS Servers
    if model.radius_servers:
        keys = sorted({k for props in model.radius_servers.values() for k in props})
        rows = [[n] + [model.radius_servers[n].get(k,'') for k in keys]
                for n in model.radius_servers]
        print_table("RADIUS Servers", ["Name"]+keys, rows)

    # User Groups
    if model.user_groups:
        keys = sorted({k for props in model.user_groups.values() for k in props})
        rows = [[n] + [model.user_groups[n].get(k,'') for k in keys]
                for n in model.user_groups]
        print_table("User Groups", ["Name"]+keys, rows)

    # Schedule Groups
    if model.schedule_groups:
        keys = sorted({k for props in model.schedule_groups.values() for k in props})
        rows = [[n] + [model.schedule_groups[n].get(k,'') for k in keys]
                for n in model.schedule_groups]
        print_table("Schedule Groups", ["Name"]+keys, rows)

    # One-time Schedules
    if model.schedule_onetime:
        keys = sorted({k for props in model.schedule_onetime.values() for k in props})
        rows = [[n] + [model.schedule_onetime[n].get(k,'') for k in keys]
                for n in model.schedule_onetime]
        print_table("One-time Schedules", ["Name"]+keys, rows)

    # Recurring Schedules
    if model.schedule_recurring:
        keys = sorted({k for props in model.schedule_recurring.values() for k in props})
        rows = [[n] + [model.schedule_recurring[n].get(k,'') for k in keys]
                for n in model.schedule_recurring]
        print_table("Recurring Schedules", ["Name"]+keys, rows)

    # Sniffer Profiles
    if model.sniffer_profile:
        keys = sorted({k for props in model.sniffer_profile.values() for k in props})
        rows = [[n] + [model.sniffer_profile[n].get(k,'') for k in keys]
                for n in model.sniffer_profile]
        print_table("Sniffer Profiles", ["Name"]+keys, rows)

    # WAN Optimization Profiles
    if model.wan_opt:
        keys = sorted({k for props in model.wan_opt.values() for k in props})
        rows = [[n] + [model.wan_opt[n].get(k,'') for k in keys]
                for n in model.wan_opt]
        print_table("WAN Optimization Profiles", ["Name"]+keys, rows)

    # FortiToken Configuration
    if model.fortitoken:
        keys = sorted({k for props in model.fortitoken.values() for k in props})
        rows = [[n] + [model.fortitoken[n].get(k,'') for k in keys]
                for n in model.fortitoken]
        print_table("FortiToken Configuration", ["Name"]+keys, rows)

    # FortiGuard Settings
    if model.fortiguard:
        rows = [[k, v] for k,v in model.fortiguard.items()]
        print_table("FortiGuard Settings", ["Setting","Value"], rows)

    # Logging Settings
    if model.log_settings:
        rows = [[k, v] for k,v in model.log_settings.items()]
        print_table("Logging Settings", ["Setting","Value"], rows)

    # SD-WAN Settings
    if model.sd_wan:
        rows = [[k, v] for k,v in model.sd_wan.items()]
        print_table("SD-WAN Settings", ["Setting","Value"], rows)

    # Load Balancing Monitors
    if model.load_balance:
        keys = sorted({k for props in model.load_balance.values() for k in props})
        rows = [[n] + [model.load_balance[n].get(k,'') for k in keys]
                for n in model.load_balance]
        print_table("Load Balancing Monitors", ["Name"]+keys, rows)

    # Wireless Controller Settings
    if model.wireless_controller:
        rows = [[k, v] for k,v in model.wireless_controller.items()]
        print_table("Wireless Controller Settings", ["Setting","Value"], rows)

    # Switch Controller Settings
    if model.switch_controller:
        rows = [[k, v] for k,v in model.switch_controller.items()]
        print_table("Switch Controller Settings", ["Setting","Value"], rows)

    # FortiSandbox Settings
    if model.sandbox:
        rows = [[k, v] for k,v in model.sandbox.items()]
        print_table("FortiSandbox Settings", ["Setting","Value"], rows)

    # SSL Certificates
    if model.certificate:
        keys = sorted({k for props in model.certificate.values() for k in props})
        rows = [[n] + [model.certificate[n].get(k,'') for k in keys]
                for n in model.certificate]
        print_table("SSL Certificates", ["Name"]+keys, rows)

    # SAML Settings
    if model.saml:
        keys = sorted({k for props in model.saml.values() for k in props})
        rows = [[n] + [model.saml[n].get(k,'') for k in keys]
                for n in model.saml]
        print_table("SAML Settings", ["Name"]+keys, rows)

    # FSSO Settings
    if model.fsso:
        keys = sorted({k for props in model.fsso.values() for k in props})
        rows = [[n] + [model.fsso[n].get(k,'') for k in keys]
                for n in model.fsso]
        print_table("FSSO Settings", ["Name"]+keys, rows)

    # Security Fabric Automation
    if model.automation:
        keys = sorted({k for props in model.automation.values() for k in props})
        rows = [[n] + [model.automation[n].get(k,'') for k in keys]
                for n in model.automation]
        print_table("Security Fabric Automation", ["Name"]+keys, rows)

    # SDN Connectors
    if model.sdn_connector:
        keys = sorted({k for props in model.sdn_connector.values() for k in props})
        rows = [[n] + [model.sdn_connector[n].get(k,'') for k in keys]
                for n in model.sdn_connector]
        print_table("SDN Connectors", ["Name"]+keys, rows)

    # FortiExtender Settings
    if model.extender:
        keys = sorted({k for props in model.extender.values() for k in props})
        rows = [[n] + [model.extender[n].get(k,'') for k in keys]
                for n in model.extender]
        print_table("FortiExtender Settings", ["Name"]+keys, rows)

    # L2TP VPN Settings
    if model.vpn_l2tp:
        rows = [[k, v] for k,v in model.vpn_l2tp.items()]
        print_table("L2TP VPN Settings", ["Setting","Value"], rows)

    # PPTP VPN Settings
    if model.vpn_pptp:
        rows = [[k, v] for k,v in model.vpn_pptp.items()]
        print_table("PPTP VPN Settings", ["Setting","Value"], rows)

    # SSL VPN Client Settings
    if model.vpn_ssl_client:
        rows = [[k, v] for k,v in model.vpn_ssl_client.items()]
        print_table("SSL VPN Client Settings", ["Setting","Value"], rows)

    # System Replacement Messages
    if model.system_replacemsg:
        rows = [[k, v] for k,v in model.system_replacemsg.items()]
        print_table("System Replacement Messages", ["Message","Content"], rows)

    # Admin Access Profiles
    if model.system_accprofile:
        keys = sorted({k for props in model.system_accprofile.values() for k in props})
        rows = [[n] + [model.system_accprofile[n].get(k,'') for k in keys]
                for n in model.system_accprofile]
        print_table("Admin Access Profiles", ["Name"]+keys, rows)

    # API Users
    if model.system_api_user:
        keys = sorted({k for props in model.system_api_user.values() for k in props})
        rows = [[n] + [model.system_api_user[n].get(k,'') for k in keys]
                for n in model.system_api_user]
        print_table("API Users", ["Name"]+keys, rows)

    # SSO Admin Settings
    if model.system_sso_admin:
        rows = [[k, v] for k,v in model.system_sso_admin.items()]
        print_table("SSO Admin Settings", ["Setting","Value"], rows)

    # Password Policy
    if model.system_password_policy:
        rows = [[k, v] for k,v in model.system_password_policy.items()]
        print_table("Password Policy", ["Setting","Value"], rows)

    # Interface Policies
    if model.system_interface_policy:
        keys = sorted({k for props in model.system_interface_policy.values() for k in props})
        rows = [[n] + [model.system_interface_policy[n].get(k,'') for k in keys]
                for n in model.system_interface_policy]
        print_table("Interface Policies", ["Name"]+keys, rows)

    # Security Fabric Settings
    if model.system_csf:
        rows = [[k, v] for k,v in model.system_csf.items()]
        print_table("Security Fabric Settings", ["Setting","Value"], rows)

    # Central Management Settings
    if model.system_central_mgmt:
        rows = [[k, v] for k,v in model.system_central_mgmt.items()]
        print_table("Central Management Settings", ["Setting","Value"], rows)

    # Auto Update Settings
    if model.system_auto_update:
        rows = [[k, v] for k,v in model.system_auto_update.items()]
        print_table("Auto Update Settings", ["Setting","Value"], rows)

    # Session TTL Settings
    if model.system_session_ttl:
        rows = [[k, v] for k,v in model.system_session_ttl.items()]
        print_table("Session TTL Settings", ["Setting","Value"], rows)

    # GRE Tunnels
    if model.system_gre_tunnel:
        keys = sorted({k for props in model.system_gre_tunnel.values() for k in props})
        rows = [[n] + [model.system_gre_tunnel[n].get(k,'') for k in keys]
                for n in model.system_gre_tunnel]
        print_table("GRE Tunnels", ["Name"]+keys, rows)

    # DDNS Settings
    if model.system_ddns:
        keys = sorted({k for props in model.system_ddns.values() for k in props})
        rows = [[n] + [model.system_ddns[n].get(k,'') for k in keys]
                for n in model.system_ddns]
        print_table("DDNS Settings", ["Name"]+keys, rows)

    # DNS Database
    if model.system_dns_database:
        keys = sorted({k for props in model.system_dns_database.values() for k in props})
        rows = [[n] + [model.system_dns_database[n].get(k,'') for k in keys]
                for n in model.system_dns_database]
        print_table("DNS Database", ["Name"]+keys, rows)

    # DNS Servers
    if model.system_dns_server:
        keys = sorted({k for props in model.system_dns_server.values() for k in props})
        rows = [[n] + [model.system_dns_server[n].get(k,'') for k in keys]
                for n in model.system_dns_server]
        print_table("DNS Servers", ["Name"]+keys, rows)

    # Proxy ARP Settings
    if model.system_proxy_arp:
        keys = sorted({k for props in model.system_proxy_arp.values() for k in props})
        rows = [[n] + [model.system_proxy_arp[n].get(k,'') for k in keys]
                for n in model.system_proxy_arp]
        print_table("Proxy ARP Settings", ["Name"]+keys, rows)

    # Virtual Wire Pairs
    if model.system_virtual_wire_pair:
        keys = sorted({k for props in model.system_virtual_wire_pair.values() for k in props})
        rows = [[n] + [model.system_virtual_wire_pair[n].get(k,'') for k in keys]
                for n in model.system_virtual_wire_pair]
        print_table("Virtual Wire Pairs", ["Name"]+keys, rows)

    # WCCP Settings
    if model.system_wccp:
        rows = [[k, v] for k,v in model.system_wccp.items()]
        print_table("WCCP Settings", ["Setting","Value"], rows)

    # SIT Tunnels
    if model.system_sit_tunnel:
        keys = sorted({k for props in model.system_sit_tunnel.values() for k in props})
        rows = [[n] + [model.system_sit_tunnel[n].get(k,'') for k in keys]
                for n in model.system_sit_tunnel]
        print_table("SIT Tunnels", ["Name"]+keys, rows)

    # IPIP Tunnels
    if model.system_ipip_tunnel:
        keys = sorted({k for props in model.system_ipip_tunnel.values() for k in props})
        rows = [[n] + [model.system_ipip_tunnel[n].get(k,'') for k in keys]
                for n in model.system_ipip_tunnel]
        print_table("IPIP Tunnels", ["Name"]+keys, rows)

    # VXLAN Settings
    if model.system_vxlan:
        keys = sorted({k for props in model.system_vxlan.values() for k in props})
        rows = [[n] + [model.system_vxlan[n].get(k,'') for k in keys]
                for n in model.system_vxlan]
        print_table("VXLAN Settings", ["Name"]+keys, rows)

    # GENEVE Settings
    if model.system_geneve:
        keys = sorted({k for props in model.system_geneve.values() for k in props})
        rows = [[n] + [model.system_geneve[n].get(k,'') for k in keys]
                for n in model.system_geneve]
        print_table("GENEVE Settings", ["Name"]+keys, rows)

    # Network Visibility Settings
    if model.system_network_visibility:
        rows = [[k, v] for k,v in model.system_network_visibility.items()]
        print_table("Network Visibility Settings", ["Setting","Value"], rows)

    # PTP Settings
    if model.system_ptp:
        rows = [[k, v] for k,v in model.system_ptp.items()]
        print_table("PTP Settings", ["Setting","Value"], rows)

    # ToS-based Priority Settings
    if model.system_tos_based_priority:
        keys = sorted({k for props in model.system_tos_based_priority.values() for k in props})
        rows = [[n] + [model.system_tos_based_priority[n].get(k,'') for k in keys]
                for n in model.system_tos_based_priority]
        print_table("ToS-based Priority Settings", ["Name"]+keys, rows)

    # Email Server Settings
    if model.system_email_server:
        rows = [[k, v] for k,v in model.system_email_server.items()]
        print_table("Email Server Settings", ["Setting","Value"], rows)

    # DNS Filter Settings
    if model.system_dns_filter:
        rows = [[k, v] for k,v in model.system_dns_filter.items()]
        print_table("DNS Filter Settings", ["Setting","Value"], rows)

    # IPS URL Filter DNS Settings
    if model.system_ips_urlfilter_dns:
        rows = [[k, v] for k,v in model.system_ips_urlfilter_dns.items()]
        print_table("IPS URL Filter DNS Settings", ["Setting","Value"], rows)

    # FortiGuard System Settings
    if model.system_fortiguard:
        rows = [[k, v] for k,v in model.system_fortiguard.items()]
        print_table("FortiGuard System Settings", ["Setting","Value"], rows)

    # FortiManager Settings
    if model.system_fm:
        rows = [[k, v] for k,v in model.system_fm.items()]
        print_table("FortiManager Settings", ["Setting","Value"], rows)

    # FortiAnalyzer Settings
    if model.system_fortianalyzer:
        rows = [[k, v] for k,v in model.system_fortianalyzer.items()]
        print_table("FortiAnalyzer Settings", ["Setting","Value"], rows)

    # FortiSandbox System Settings
    if model.system_fortisandbox:
        rows = [[k, v] for k,v in model.system_fortisandbox.items()]
        print_table("FortiSandbox System Settings", ["Setting","Value"], rows)

    # Generate network diagram
    generator = NetworkDiagramGenerator(model)
    generator.generate_diagram()

if __name__ == '__main__':
    main()
