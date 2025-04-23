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
        self.graph = Digraph(comment='FortiGate Network Topology - Used Objects')
        self.graph.attr(rankdir='TB')  # Top to bottom layout for better network hierarchy
        self._setup_graph_attributes()
        self.address_groups_expanded = {}
        self.service_groups_expanded = {}
        self.processed_nodes = set()  # Track processed nodes to avoid duplicates

        # Sets to track used objects
        self.used_addresses = set()
        self.used_addr_groups = set()
        self.used_services = set()
        self.used_svc_groups = set()
        self.used_interfaces = set()
        self.used_zones = set()
        self.used_vips = set()
        self.used_ippools = set()
        self.used_routes = set() # Track used static routes
        self.used_phase1 = set()
        self.used_phase2 = set()
        self.used_dhcp_servers = set() # Track by ID

        # Relationship stats (might only reflect used objects later)
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
        # Only add edge if both source and destination nodes exist in the processed set
        if src in self.processed_nodes and dst in self.processed_nodes:
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
        """Add used zones and their interface relationships."""
        # Create zones section if there are used zones
        used_zone_names = [name for name in self.model.zones if name in self.used_zones]
        if not used_zone_names:
            return

        with self.graph.subgraph(name='cluster_zones') as zones:
            zones.attr(**self.CLUSTER_STYLE)
            zones.attr(label='Security Zones (Used)')
            for name in used_zone_names:
                interfaces = self.model.zones[name]
                # Filter interfaces to only show used ones within the zone label
                used_interfaces_in_zone = [iface for iface in interfaces if iface in self.used_interfaces]
                
                zone_label = [f"Zone: {name}"]
                if used_interfaces_in_zone:
                    zone_label.append(f"Used Interfaces: {', '.join(used_interfaces_in_zone)}")
                
                # Create a subgraph for each zone to group its contents visually if desired, or just add the node
                # Using a simple node for clarity here
                self._add_node(f"zone_{name}", label='\\n'.join(zone_label), **self.ZONE_STYLE)

                # Connect zone to its USED interfaces
                for iface in used_interfaces_in_zone:
                    # Ensure interface node exists before adding edge
                    if f"iface_{iface}" in self.processed_nodes:
                         # Style: Zone to Interface connection (Network Structure)
                         self._add_edge(f"zone_{name}", f"iface_{iface}", 
                                        color='#007bff', penwidth='1.5', 
                                        tooltip=f"Zone {name} contains Interface {iface}")


    def generate_address_objects(self):
        """Add used address objects and groups to the diagram."""
        # Create addresses section if there are used addresses/groups
        if not self.used_addresses and not self.used_addr_groups:
            return

        with self.graph.subgraph(name='cluster_addresses_main') as addresses_cluster:
             addresses_cluster.attr(**self.CLUSTER_STYLE)
             addresses_cluster.attr(label='Address Objects (Used)')

             # Add individual addresses IF USED
             for name, addr_data in self.model.addresses.items():
                 if name in self.used_addresses:
                     label = [f"Address: {name}"]
                     if 'type' in addr_data:
                         label.append(f"Type: {addr_data['type']}")
                     if 'subnet' in addr_data:
                         label.append(f"Subnet: {self._get_subnet_label(addr_data['subnet'])}")
                     if 'comment' in addr_data and addr_data['comment']:
                         label.append(f"Comment: {addr_data['comment']}")
                     
                     self._add_node(f"addr_{name}", label='\\n'.join(label), **self.NETWORK_STYLE)

             # Add address groups IF USED
             for name, members in self.model.addr_groups.items():
                 if name in self.used_addr_groups:
                     # Only expand relevant members (those that are also used) for label count?
                     # Let's keep the original count for simplicity for now.
                     expanded_members = self._expand_address_group(name)
                     label = [f"Address Group: {name}",
                             f"Total Members: {len(expanded_members)}"] # Label reflects total members
                     
                     self._add_node(f"addrgrp_{name}", label='\\n'.join(label), **self.GROUP_STYLE)

                     # Connect group to its immediate members (only if member is also used)
                     for member in members:
                         member_node_prefix = None
                         member_is_used = False
                         if member in self.model.addresses:
                             member_node_prefix = "addr_"
                             member_is_used = member in self.used_addresses
                         elif member in self.model.addr_groups:
                             member_node_prefix = "addrgrp_"
                             member_is_used = member in self.used_addr_groups
                         
                         if member_is_used and member_node_prefix:
                             # Ensure target node exists before adding edge
                             if f"{member_node_prefix}{member}" in self.processed_nodes:
                                  # Style: Group Membership (Address)
                                  self._add_edge(f"addrgrp_{name}", f"{member_node_prefix}{member}", 
                                                 color='#6c757d', style='dotted', arrowhead='empty', 
                                                 tooltip=f"Group {name} includes {member}")


    def generate_services(self):
        """Add used services and service groups to the diagram."""
        # Create services section if there are used services/groups
        if not self.used_services and not self.used_svc_groups:
            return

        with self.graph.subgraph(name='cluster_services_main') as services_cluster:
            services_cluster.attr(**self.CLUSTER_STYLE)
            services_cluster.attr(label='Services (Used)')

            # Add individual services IF USED
            for name, svc_data in self.model.services.items():
                if name in self.used_services:
                    label = [f"Service: {name}"]
                    if 'protocol' in svc_data:
                        label.append(f"Protocol: {svc_data['protocol']}")
                    if 'port' in svc_data:
                        label.append(f"Port: {svc_data['port']}")
                    if 'comment' in svc_data and svc_data['comment']:
                        label.append(f"Comment: {svc_data['comment']}")
                    
                    self._add_node(f"svc_{name}", label='\\n'.join(label), **self.SERVICE_STYLE)

            # Add service groups IF USED
            for name, members in self.model.svc_groups.items():
                if name in self.used_svc_groups:
                    expanded_members = self._expand_service_group(name)
                    label = [f"Service Group: {name}",
                            f"Total Members: {len(expanded_members)}"]
                            
                    self._add_node(f"svcgrp_{name}", label='\\n'.join(label), **self.GROUP_STYLE)
                    
                    # Connect group to its immediate members (only if member is also used)
                    for member in members:
                        member_node_prefix = None
                        member_is_used = False
                        if member in self.model.services:
                            member_node_prefix = "svc_"
                            member_is_used = member in self.used_services
                        elif member in self.model.svc_groups:
                            member_node_prefix = "svcgrp_"
                            member_is_used = member in self.used_svc_groups

                        if member_is_used and member_node_prefix:
                            if f"{member_node_prefix}{member}" in self.processed_nodes:
                                # Style: Group Membership (Service)
                                self._add_edge(f"svcgrp_{name}", f"{member_node_prefix}{member}", 
                                               color='#6c757d', style='dotted', arrowhead='empty', 
                                               tooltip=f"Group {name} includes {member}")


    def generate_routes(self):
        """Add used static routes to the diagram."""
        used_route_indices = [idx for idx, route in enumerate(self.model.routes) if idx in self.used_routes]
        if not used_route_indices:
             return

        with self.graph.subgraph(name='cluster_static_routes') as static_routes:
            static_routes.attr(**self.CLUSTER_STYLE)
            static_routes.attr(label='Static Routes (Used)')
            
            for idx in used_route_indices:
                route = self.model.routes[idx]
                # Use index or a generated name for uniqueness if 'name' isn't reliable
                route_node_name = f"route_{route.get('name', idx)}" # Use index if name missing
                
                dst = self._get_subnet_label(route.get('dst', ''))
                gw = route.get('gateway', '')
                device = route.get('device', '')
                distance = route.get('distance', '')
                
                label = [f"Route: {route.get('name', f'ID:{idx}')}"] # Display name or ID
                if dst: label.append(f"Destination: {dst}")
                if gw: label.append(f"Gateway: {gw}")
                if device: label.append(f"Interface: {device}") # Show interface in label
                if distance: label.append(f"Distance: {distance}")
                if route.get('comment'): label.append(f"Comment: {route['comment']}")
                    
                self._add_node(route_node_name, label='\\n'.join(label), **self.ROUTE_STYLE)
                
                # Connect route to its interface IF the interface is also used/drawn
                if device and f"iface_{device}" in self.processed_nodes:
                     # Style: Route pointing to its egress interface
                     self._add_edge(route_node_name, f"iface_{device}", 
                                    color='#fd7e14', penwidth='1.2', arrowhead='normal', 
                                    tooltip=f"Route via {device}")

    def generate_vips(self):
        """Add used virtual IPs to the diagram."""
        used_vip_names = [name for name in self.model.vips if name in self.used_vips]
        if not used_vip_names:
            return

        with self.graph.subgraph(name='cluster_vips') as vips:
            vips.attr(**self.CLUSTER_STYLE)
            vips.attr(label='Virtual IPs (Used)')
            
            for name in used_vip_names:
                vip = self.model.vips[name]
                label = [f"VIP: {name}"]
                if 'extip' in vip: label.append(f"External IP: {vip['extip']}")
                if 'mappedip' in vip: label.append(f"Mapped IP: {vip['mappedip']}")
                if 'portforward' in vip and vip['portforward'] == 'enable':
                     label.append(f"Port Fwd: {vip.get('protocol','')} {vip.get('extport','')}->{vip.get('mappedport','')}")
                elif 'protocol' in vip: # Show protocol if no port forward
                     label.append(f"Protocol: {vip['protocol']}")
                if 'comment' in vip: label.append(f"Comment: {vip['comment']}")

                self._add_node(f"vip_{name}", label='\\n'.join(label), **self.VIP_STYLE)
                
                # Connect VIP to relevant interface if specified AND interface is used
                if 'interface' in vip and f"iface_{vip['interface']}" in self.processed_nodes:
                    # Edge direction: Interface -> VIP makes sense conceptually
                    # Style: Interface hosting a VIP
                    self._add_edge(f"iface_{vip['interface']}", f"vip_{name}", 
                                   color='#6f42c1', penwidth='1.2', arrowhead='none', 
                                   tooltip=f"Interface {vip['interface']} hosts VIP {name}")

    def generate_ip_pools(self):
        """Add used IP pools to the diagram."""
        used_pool_names = [name for name in self.model.ippools if name in self.used_ippools]
        if not used_pool_names:
            return

        with self.graph.subgraph(name='cluster_pools') as pools:
            pools.attr(**self.CLUSTER_STYLE)
            pools.attr(label='IP Pools (Used)')
            
            for name in used_pool_names:
                pool = self.model.ippools[name]
                label = [f"Pool: {name}"]
                if 'startip' in pool and 'endip' in pool:
                    label.append(f"Range: {pool['startip']}-{pool['endip']}")
                if 'type' in pool: label.append(f"Type: {pool['type']}")
                if 'comment' in pool and pool['comment']: label.append(f"Comment: {pool['comment']}")
                    
                self._add_node(f"pool_{name}", label='\\n'.join(label), **self.POOL_STYLE)
                # Note: Connections to IP Pools (e.g., from Policies) are handled in generate_policies

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
        """Generate the network hierarchy using only used components."""
        # Check if any network components are used
        if not self.used_zones and not self.used_interfaces and not self.used_routes and not self.used_phase1:
             # Maybe add SD-WAN check here too
             return

        with self.graph.subgraph(name='cluster_network_main') as network_cluster:
             network_cluster.attr(**self.CLUSTER_STYLE)
             network_cluster.attr(label='Network Topology (Used Components)')
             
             # Create zones section (calls generate_zones which filters)
             self.generate_zones()
             
             # Create interfaces section (calls generate_interfaces which filters)
             self.generate_interfaces()
             
             # Create routing section
             # Check if any routing components are used
             if self.used_routes or (hasattr(self.model, 'sd_wan') and self.model.sd_wan): # Add more checks if needed (BGP, OSPF etc)
                 with network_cluster.subgraph(name='cluster_routing') as routing:
                     routing.attr(**self.CLUSTER_STYLE)
                     routing.attr(label='Routing (Used)')
                     
                     # Static routes subsection (calls generate_routes which filters)
                     self.generate_routes()
                     
                     # SD-WAN subsection (calls generate_sd_wan which filters)
                     self.generate_sd_wan()
             
             # Create VPN section
             # Check if any VPN components are used
             if self.used_phase1 or self.used_phase2:
                 with network_cluster.subgraph(name='cluster_vpn') as vpn:
                     vpn.attr(**self.CLUSTER_STYLE)
                     vpn.attr(label='VPN Configuration (Used)')
                     self.generate_vpn_tunnels() # This needs filtering internally


    def generate_security_configuration(self):
        """Generate the security configuration using only used components."""
         # Check if any security components are used (addresses, services, policies)
        if not self.model.policies and not self.used_addresses and not self.used_addr_groups \
           and not self.used_services and not self.used_svc_groups:
            return

        with self.graph.subgraph(name='cluster_security_main') as security_cluster:
            security_cluster.attr(**self.CLUSTER_STYLE)
            security_cluster.attr(label='Security Configuration (Used Components)')

            # Create address objects section (calls generate_address_objects which filters)
            self.generate_address_objects()
            
            # Create services section (calls generate_services which filters)
            self.generate_services()
            
            # Create policies section (calls generate_policies which filters connections)
            self.generate_policies()


    def generate_nat_configuration(self):
        """Generate NAT configuration using only used components."""
        # Check if any NAT components are used
        if not self.used_vips and not self.used_ippools:
            return

        with self.graph.subgraph(name='cluster_nat_main') as nat_cluster:
            nat_cluster.attr(**self.CLUSTER_STYLE)
            nat_cluster.attr(label='NAT Configuration (Used Components)')

            # Create VIPs section (calls generate_vips which filters)
            self.generate_vips()
            
            # Create IP Pools section (calls generate_ip_pools which filters)
            self.generate_ip_pools()


    def generate_sd_wan(self):
        """Generate SD-WAN configuration if present and involves used interfaces."""
        # Check if SD-WAN config exists and if any of its members are in used_interfaces
        sd_wan_config = getattr(self.model, 'sd_wan', {})
        if not sd_wan_config:
             return
             
        member_interfaces = sd_wan_config.get('members', []) # Assuming list of interface names
        used_member_interfaces = [iface for iface in member_interfaces if iface in self.used_interfaces]

        if not used_member_interfaces: # Only draw SD-WAN if it connects to used interfaces
             return

        # Create SD-WAN node if it's relevant
        sdwan_node_name = 'sd_wan_control' # Example node name for the SD-WAN logic itself
        label = ['SD-WAN Controller'] # Simple label
        if 'status' in sd_wan_config: label.append(f"Status: {sd_wan_config['status']}")
        if 'load-balance-mode' in sd_wan_config: label.append(f"Mode: {sd_wan_config['load-balance-mode']}")
            
        self._add_node(sdwan_node_name, label='\\n'.join(label), **self.SD_WAN_STYLE)

        # Connect SD-WAN node to USED member interfaces
        for iface_name in used_member_interfaces:
            if f"iface_{iface_name}" in self.processed_nodes:
                 # Style: SD-WAN control to member interface
                 self._add_edge(sdwan_node_name, f"iface_{iface_name}", label="Member", 
                                color='#28a745', penwidth='1.2', style='dashed', arrowhead='none', 
                                tooltip=f"SD-WAN includes {iface_name}")


    def generate_vpn_tunnels(self):
        """Generate VPN tunnel configuration for used tunnels."""
        # Add Phase 1 tunnels if used
        used_p1_names = [name for name in self.model.phase1 if name in self.used_phase1]
        if used_p1_names:
            with self.graph.subgraph(name='cluster_vpn_p1') as vpn_p1:
                vpn_p1.attr(**self.CLUSTER_STYLE)
                vpn_p1.attr(label='IPsec Phase 1 (Used)')
                for name in used_p1_names:
                    phase1 = self.model.phase1[name]
                    p1_node_name = f"vpn_p1_{name}"
                    label = [f"P1 VPN: {name}"]
                    if 'interface' in phase1: label.append(f"Interface: {phase1['interface']}")
                    if 'remote-gw' in phase1: label.append(f"Remote GW: {phase1['remote-gw']}")
                    if 'proposal' in phase1: label.append(f"Proposal: {phase1['proposal']}") # Example detail
                    
                    self._add_node(p1_node_name, label='\\n'.join(label), **self.VPN_STYLE)
                    
                    # Connect VPN to interface IF interface is used
                    if 'interface' in phase1 and f"iface_{phase1['interface']}" in self.processed_nodes:
                        # Style: VPN P1 bound to Interface
                        self._add_edge(p1_node_name, f"iface_{phase1['interface']}", 
                                       color='#17a2b8', penwidth='1.2', style='solid', arrowhead='none', 
                                       tooltip=f"P1 {name} uses Interface {phase1['interface']}")

        # Add Phase 2 tunnels if used (connecting to their Phase 1)
        used_p2_names = [name for name in self.model.phase2 if name in self.used_phase2]
        if used_p2_names:
             with self.graph.subgraph(name='cluster_vpn_p2') as vpn_p2:
                vpn_p2.attr(**self.CLUSTER_STYLE)
                vpn_p2.attr(label='IPsec Phase 2 (Used)')
                for name in used_p2_names:
                    phase2 = self.model.phase2[name]
                    p2_node_name = f"vpn_p2_{name}"
                    p1_proposal_name = phase2.get('proposal', 'default') # Assuming proposal links P1/P2? Or is it name convention?
                    # Fortinet links P2 to P1 via 'phase1name' field within P2 config
                    p1_name = phase2.get('phase1name')
                    
                    label = [f"P2 VPN: {name}"]
                    # Add P2 specific details like selectors if available and relevant
                    src_sel = phase2.get('src_subnet', phase2.get('src_name', 'any')) # Simplified selector view
                    dst_sel = phase2.get('dst_subnet', phase2.get('dst_name', 'any'))
                    label.append(f"Selectors: {src_sel} <-> {dst_sel}")
                    
                    # Create a style dict based on VPN_STYLE but override shape
                    p2_style = self.VPN_STYLE.copy()
                    p2_style['shape'] = 'note' # Override shape for P2 tunnels
                    self._add_node(p2_node_name, label='\\n'.join(label), **p2_style)

                    # Connect P2 to its P1 IF P1 is drawn
                    if p1_name and f"vpn_p1_{p1_name}" in self.processed_nodes:
                         # Style: P1 defines P2
                         self._add_edge(f"vpn_p1_{p1_name}", p2_node_name, 
                                        style='dashed', color='#17a2b8', arrowhead='normal', 
                                        tooltip=f"P1 {p1_name} defines P2 {name}")
                         
                    # Optional: Connect P2 selectors to address objects if they are used/drawn
                    # This requires parsing src/dst_name and checking used_addresses/used_addr_groups
                    # Example (needs refinement based on actual parser output for phase2 selectors):
                    # if phase2.get('src_addr_type') == 'name':
                    #     for addr_name in phase2.get('src_name', []):
                    #         if f"addr_{addr_name}" in self.processed_nodes: self._add_edge(p2_node_name, f"addr_{addr_name}", label="src")
                    #         if f"addrgrp_{addr_name}" in self.processed_nodes: self._add_edge(p2_node_name, f"addrgrp_{addr_name}", label="src")
                    # Similar logic for dst_name...


    def generate_interfaces(self):
        """Add used interfaces to the diagram with enhanced details."""
        used_interface_names = [name for name in self.model.interfaces if name in self.used_interfaces]
        if not used_interface_names:
            return

        with self.graph.subgraph(name='cluster_interfaces') as interfaces:
            interfaces.attr(**self.CLUSTER_STYLE)
            interfaces.attr(label='Network Interfaces (Used)')
            
            for name in used_interface_names:
                iface = self.model.interfaces[name]
                iface_node_name = f"iface_{name}"
                
                # Create detailed interface label
                label_parts = [f"Interface: {name}"]
                if 'ip' in iface and iface['ip']: label_parts.append(f"IP: {iface['ip']}")
                if 'type' in iface: label_parts.append(f"Type: {iface['type']}")
                if 'allowaccess' in iface and iface['allowaccess']: label_parts.append(f"Access: {','.join(iface['allowaccess'])}")
                if 'status' in iface: label_parts.append(f"Status: {iface['status']}")
                if 'role' in iface: label_parts.append(f"Role: {iface['role']}")
                if 'vdom' in iface: label_parts.append(f"VDOM: {iface['vdom']}")
                if 'alias' in iface: label_parts.append(f"Alias: {iface['alias']}")
                
                self._add_node(iface_node_name, label='\\n'.join(label_parts), **self.INTERFACE_STYLE)
                
                # Add VLAN information if applicable and the VLAN interface *itself* is used
                # Assuming VLANs might be separate interface entries like 'port1.10' or handled differently.
                # The current code models VLANs separately in model.vlans linked by 'interface'.
                # Let's check if a VLAN associated with this *physical* interface exists and is *used*.
                
                # Find VLANs associated with this physical interface
                associated_vlans = {vlan_name: vlan_data for vlan_name, vlan_data in self.model.vlans.items()
                                     if vlan_data.get('interface') == name}
                                     
                for vlan_name, vlan_data in associated_vlans.items():
                     # Assume a VLAN interface might be named directly (e.g., 'vlan10') and checked in used_interfaces
                     # Or perhaps the policy references the physical interface but traffic matches the VLAN ID?
                     # Let's draw the VLAN node *if the physical interface is drawn* and link them.
                     # We need a better way to determine if a VLAN *config* is actually "used".
                     # For now, link if physical is drawn.
                     vlan_node_name = f"vlan_{vlan_name}"
                     vlan_label_parts = [
                         f"VLAN: {vlan_name}",
                         f"ID: {vlan_data.get('vlanid', '')}",
                         # f"Members: {','.join(vlan.get('members', []))}" # Port members less relevant here
                     ]
                     # Add VLAN node (maybe different style?)
                     self._add_node(vlan_node_name, label='\\n'.join(vlan_label_parts), shape='tab', fillcolor='#ddeeff', color='blue')
                     # Link physical interface to its VLAN config node
                     # Style: Physical Interface hosting VLAN
                     self._add_edge(iface_node_name, vlan_node_name, 
                                    style='dotted', color='#0056b3', arrowhead='none', 
                                    tooltip=f"Interface {name} hosts VLAN {vlan_name}")


    def generate_policies(self):
        """Add firewall policies and connect used elements."""
        if not self.model.policies:
            return
            
        with self.graph.subgraph(name='cluster_policies') as policies:
            policies.attr(**self.CLUSTER_STYLE)
            policies.attr(label='Security Policies')
            
            for policy in self.model.policies:
                # Check if policy has any connection to drawn elements (interfaces/zones)
                # This prevents drawing completely orphaned policies
                policy_id = policy.get('id', '')
                policy_node_name = f"policy_{policy_id}"
                
                src_connections = policy.get('srcintf', []) + policy.get('srcaddr', [])
                dst_connections = policy.get('dstintf', []) + policy.get('dstaddr', [])
                svc_connections = policy.get('service', [])
                
                # Basic check: Is at least one src/dst interface/zone drawn?
                src_intf_drawn = any(f"iface_{i}" in self.processed_nodes or f"zone_{i}" in self.processed_nodes for i in policy.get('srcintf',[]))
                dst_intf_drawn = any(f"iface_{i}" in self.processed_nodes or f"zone_{i}" in self.processed_nodes for i in policy.get('dstintf',[]))

                if not src_intf_drawn and not dst_intf_drawn:
                    # print(f"Skipping policy {policy_id} as its interfaces/zones are not drawn.")
                    continue # Skip policy if its interfaces aren't shown

                # Create detailed policy label (same as before)
                action = policy.get('action', 'N/A')
                action_symbol = '✓' if action == 'accept' else ('✗' if action == 'deny' else '?')
                label_parts = [f"{action_symbol} Policy {policy_id}"] # Add symbol here
                label_parts.append(f"Action: {policy.get('action', 'N/A')}")
                if policy.get('nat') == 'enable': label_parts.append("NAT: Enabled")
                if policy.get('ippool') == 'enable': label_parts.append(f"Pool: {policy.get('poolname', 'N/A')}")
                label_parts.append(f"Status: {policy.get('status', 'N/A')}")
                if 'schedule' in policy and policy['schedule'] != 'always': label_parts.append(f"Schedule: {policy['schedule']}")
                if 'comments' in policy and policy['comments']: label_parts.append(f"Comments: {policy['comments']}")
                
                # Add policy node
                self._add_node(policy_node_name,
                             label='\\n'.join(label_parts),
                             **self.POLICY_STYLE)
                
                # Connect policy elements only if they are drawn
                self._connect_policy_elements(policy, 'src', policy_id)
                self._connect_policy_elements(policy, 'dst', policy_id)
                self._connect_policy_services(policy, policy_id)
                # Connect IP Pool if used and drawn
                if policy.get('nat') == 'enable' and policy.get('ippool') == 'enable':
                    poolname = policy.get('poolname')
                    if poolname and f"pool_{poolname}" in self.processed_nodes:
                         # Style: Policy using IP Pool for NAT
                         self._add_edge(policy_node_name, f"pool_{poolname}", 
                                        label="uses pool", style='dashed', color='#ff8c00', arrowhead='normal', 
                                        tooltip=f"Policy {policy_id} uses NAT Pool {poolname}")

    def _connect_policy_elements(self, policy_data, direction, policy_id):
        """Helper method to connect policy elements if they are drawn."""
        policy_node_name = f"policy_{policy_id}"
        intf_key = f"{direction}intf"
        addr_key = f"{direction}addr"
        
        # Connect interfaces/zones IF DRAWN
        for name in policy_data.get(intf_key, []):
            node_name = None
            if name in self.model.zones and f"zone_{name}" in self.processed_nodes:
                 node_name = f"zone_{name}"
            elif name in self.model.interfaces and f"iface_{name}" in self.processed_nodes:
                 node_name = f"iface_{name}"

            if node_name:
                if direction == 'src':
                    # Style: Source Interface/Zone to Policy
                    self._add_edge(node_name, policy_node_name, 
                                   color='#20c997', penwidth='1.3', arrowhead='normal', 
                                   tooltip=f"Source for Policy {policy_id}")
                else:
                    # Style: Policy to Destination Interface/Zone
                    self._add_edge(policy_node_name, node_name, 
                                   color='#e83e8c', penwidth='1.3', arrowhead='normal', 
                                   tooltip=f"Destination for Policy {policy_id}")
        
        # Connect addresses/groups IF DRAWN
        for name in policy_data.get(addr_key, []):
            node_name = None
            if name in self.model.addresses and f"addr_{name}" in self.processed_nodes:
                 node_name = f"addr_{name}"
            elif name in self.model.addr_groups and f"addrgrp_{name}" in self.processed_nodes:
                 node_name = f"addrgrp_{name}"
            elif name in self.model.vips and f"vip_{name}" in self.processed_nodes: # Check if VIP is used as address
                 node_name = f"vip_{name}"

            if node_name:
                edge_label = "src" if direction == 'src' else "dst"
                edge_tooltip = f"{direction.capitalize()} Address/VIP for Policy {policy_id}"
                if direction == 'src':
                    # Style: Source Address/Group/VIP to Policy
                    self._add_edge(node_name, policy_node_name, label=edge_label, 
                                   color='#28a745', style='dashed', arrowhead='none', penwidth='1.0', 
                                   tooltip=edge_tooltip)
                else:
                    # Style: Policy to Destination Address/Group/VIP
                    self._add_edge(policy_node_name, node_name, label=edge_label, 
                                   color='#dc3545', style='dashed', arrowhead='none', penwidth='1.0', 
                                   tooltip=edge_tooltip)

    def _connect_policy_services(self, policy_data, policy_id):
        """Helper method to connect policy services IF DRAWN."""
        policy_node_name = f"policy_{policy_id}"
        for name in policy_data.get('service', []):
            node_name = None
            if name in self.model.services and f"svc_{name}" in self.processed_nodes:
                 node_name = f"svc_{name}"
            elif name in self.model.svc_groups and f"svcgrp_{name}" in self.processed_nodes:
                 node_name = f"svcgrp_{name}"
                 
            if node_name:
                # Style: Service allowed by Policy
                self._add_edge(node_name, policy_node_name, label="allows", 
                               color='#6610f2', style='dotted', arrowhead='none', penwidth='1.0', 
                               tooltip=f"Service {name} allowed by Policy {policy_id}")


    def analyze_relationships(self):
        """Analyze relationships and identify used objects."""
        # Reset used sets
        self.used_addresses = set()
        self.used_addr_groups = set()
        self.used_services = set()
        self.used_svc_groups = set()
        self.used_interfaces = set()
        self.used_zones = set()
        self.used_vips = set()
        self.used_ippools = set()
        self.used_routes = set()
        self.used_phase1 = set()
        self.used_phase2 = set()
        self.used_dhcp_servers = set()
        
        print("Analyzing configuration relationships to identify used objects...")

        # --- Helper for recursive group expansion ---
        def add_used_address_object(name):
            if name in self.model.addresses:
                if name not in self.used_addresses:
                    self.used_addresses.add(name)
                    # print(f"  Marked Address used: {name}")
            elif name in self.model.addr_groups:
                if name not in self.used_addr_groups: # Avoid redundant recursion
                    self.used_addr_groups.add(name)
                    # print(f"  Marked AddrGroup used: {name}")
                    for member in self.model.addr_groups.get(name, []):
                        add_used_address_object(member) # Recurse

        def add_used_service_object(name):
            if name in self.model.services:
                 if name not in self.used_services:
                    self.used_services.add(name)
                    # print(f"  Marked Service used: {name}")
            elif name in self.model.svc_groups:
                if name not in self.used_svc_groups: # Avoid redundant recursion
                    self.used_svc_groups.add(name)
                    # print(f"  Marked SvcGroup used: {name}")
                    for member in self.model.svc_groups.get(name, []):
                        add_used_service_object(member) # Recurse

        # --- Analyze Policies ---
        # print("Analyzing Policies...")
        for policy in self.model.policies:
            policy_id = policy.get('id', '')
            # print(f" Policy {policy_id}:")
            is_policy_active = policy.get('status', 'enable') == 'enable' # Only consider enabled policies for usage? Let's include disabled for now.

            # Track interfaces/zones used by policy
            policy_interfaces = set()
            for intf in policy.get('srcintf', []) + policy.get('dstintf', []):
                if intf in self.model.zones:
                    self.used_zones.add(intf)
                    # print(f"  Zone used: {intf}")
                    # Mark interfaces within the used zone as used
                    for zone_member_iface in self.model.zones.get(intf, []):
                         if zone_member_iface in self.model.interfaces:
                              self.used_interfaces.add(zone_member_iface)
                              policy_interfaces.add(zone_member_iface)
                              # print(f"    Interface (via zone {intf}) used: {zone_member_iface}")
                elif intf in self.model.interfaces:
                     self.used_interfaces.add(intf)
                     policy_interfaces.add(intf)
                     # print(f"  Interface used: {intf}")

            # Track addresses/groups used by policy
            for addr in policy.get('srcaddr', []) + policy.get('dstaddr', []):
                add_used_address_object(addr)
                # If addr is a VIP, mark it as used
                if addr in self.model.vips:
                    self.used_vips.add(addr)
                    # print(f"  VIP (as address) used: {addr}")
                    # Also mark the VIP's interface as used, if the interface exists
                    vip_data = self.model.vips[addr]
                    vip_intf = vip_data.get('interface')
                    if vip_intf and vip_intf in self.model.interfaces:
                        self.used_interfaces.add(vip_intf)
                        # print(f"    Interface (via VIP {addr}) used: {vip_intf}")


            # Track services/groups used by policy
            for svc in policy.get('service', []):
                add_used_service_object(svc)

            # Track IP Pools used for NAT
            if policy.get('nat') == 'enable' and policy.get('ippool') == 'enable':
                 poolname = policy.get('poolname') # Assuming this field exists
                 if poolname and poolname in self.model.ippools:
                      self.used_ippools.add(poolname)
                      # print(f"  IP Pool used: {poolname}")


        # --- Analyze Static Routes ---
        # print("Analyzing Static Routes...")
        for idx, route in enumerate(self.model.routes):
            device = route.get('device', '')
            status = route.get('status', 'enable')
            if status == 'enable' and device and device in self.model.interfaces:
                # Mark route as used IF its interface is marked used by something else (e.g., policy)
                if device in self.used_interfaces:
                     self.used_routes.add(idx) # Use index as identifier
                     # print(f"  Route {idx} used (via interface {device})")
                # else: # Optionally, mark the interface used *because* a route uses it
                #     self.used_interfaces.add(device)
                #     self.used_routes.add(idx)
                #     print(f"  Route {idx} used (marks interface {device} as used)")
                # Let's stick to the first approach: only show routes connected to already-used interfaces.


        # --- Analyze VIPs (standalone usage) ---
        # print("Analyzing VIPs...")
        for name, vip in self.model.vips.items():
             # Mark VIP used if its interface is marked used by something else.
             vip_intf = vip.get('interface')
             if vip_intf and vip_intf in self.used_interfaces:
                 if name not in self.used_vips: # If not already marked by policy
                     self.used_vips.add(name)
                     # print(f"  VIP {name} used (via used interface {vip_intf})")


        # --- Analyze DHCP Servers ---
        # print("Analyzing DHCP Servers...")
        for idx, server in enumerate(self.model.dhcp_servers): # Assuming list model
            server_id = server.get('id') # Get the unique ID if available
            interface = server.get('interface', '')
            status = server.get('status', 'enable')
            if status == 'enable' and interface and interface in self.model.interfaces:
                 # Mark DHCP server used if its interface is used
                 if interface in self.used_interfaces and server_id:
                     self.used_dhcp_servers.add(server_id) # Use ID
                     # print(f"  DHCP Server {server_id} used (via interface {interface})")
                 # Optionally mark interface used because of DHCP
                 # elif server_id:
                 #     self.used_interfaces.add(interface)
                 #     self.used_dhcp_servers.add(server_id)
                 #     print(f"  DHCP Server {server_id} used (marks interface {interface} as used)")


        # --- Analyze VPNs ---
        # print("Analyzing VPNs...")
        # Mark Phase 1 used if its interface is used AND it's enabled
        for name, phase1 in self.model.phase1.items():
            interface = phase1.get('interface', '')
            status = phase1.get('status', 'enable')
            if status == 'enable' and interface and interface in self.used_interfaces:
                self.used_phase1.add(name)
                # print(f"  Phase 1 {name} used (via interface {interface})")
            # Optionally mark interface used by VPN
            # elif status == 'enable' and interface and interface in self.model.interfaces:
            #     self.used_interfaces.add(interface)
            #     self.used_phase1.add(name)
            #     print(f"  Phase 1 {name} used (marks interface {interface} as used)")


        # Mark Phase 2 used if its Phase 1 is used AND it's enabled
        for name, phase2 in self.model.phase2.items():
            p1_name = phase2.get('phase1name')
            status = phase2.get('status', 'enable')
            if status == 'enable' and p1_name and p1_name in self.used_phase1:
                 self.used_phase2.add(name)
                 # print(f"  Phase 2 {name} used (via phase 1 {p1_name})")
                 # Also mark selectors as used if they are address objects/groups
                 if phase2.get('src_addr_type') == 'name':
                     for addr_name in phase2.get('src_name', []): add_used_address_object(addr_name)
                 if phase2.get('dst_addr_type') == 'name':
                      for addr_name in phase2.get('dst_name', []): add_used_address_object(addr_name)


        # --- Analyze SD-WAN ---
        # print("Analyzing SD-WAN...")
        sd_wan_config = getattr(self.model, 'sd_wan', {})
        if sd_wan_config.get('status') == 'enable':
            member_interfaces = sd_wan_config.get('members', []) # Assuming list of interface names/indices
            # Check parser for actual member format (index or name)
            # Assume names for now:
            for member_iface_name in member_interfaces:
                if member_iface_name in self.model.interfaces:
                    # Mark interface as used due to being an SD-WAN member
                    if member_iface_name not in self.used_interfaces:
                         self.used_interfaces.add(member_iface_name)
                         # print(f"  Interface {member_iface_name} used (via SD-WAN membership)")
            # Also analyze SD-WAN rules/services for interface/address/service usage if parser supports them


        # --- Re-Analyze Zones ---
        # Ensure a zone is marked used if ANY of its member interfaces are used
        for zone_name, member_interfaces in self.model.zones.items():
            if zone_name not in self.used_zones: # If not already marked by policy
                for iface in member_interfaces:
                    if iface in self.used_interfaces:
                        self.used_zones.add(zone_name)
                        # print(f"  Zone {zone_name} used (contains used interface {iface})")
                        break # No need to check other members

        # --- Relationship Stats (Based on FULL model for now) ---
        # print("Calculating Relationship Stats (full model)...")
        # Original stats calculation remains unchanged for now.
        # Consider filtering stats later if needed.
        # Zone Analysis
        self.relationship_stats['zone_interface_count'] = {
            zone: len(interfaces) for zone, interfaces in self.model.zones.items()
        }
        # Policy Analysis
        self.relationship_stats['policy_address_count'] = {}
        self.relationship_stats['policy_service_count'] = {}
        for policy in self.model.policies:
            policy_id = policy.get('id', '')
            self.relationship_stats['policy_address_count'][policy_id] = {
                'src': len(policy.get('srcaddr', [])),
                'dst': len(policy.get('dstaddr', []))
            }
            self.relationship_stats['policy_service_count'][policy_id] = len(policy.get('service', []))
        # Interface Usage Analysis
        self.relationship_stats['interface_policy_count'] = {}
        for policy in self.model.policies:
            for intf in policy.get('srcintf', []) + policy.get('dstintf', []):
                # Use interface name directly as key
                 self.relationship_stats['interface_policy_count'][intf] = \
                     self.relationship_stats['interface_policy_count'].get(intf, 0) + 1
        # Address Usage Analysis
        self.relationship_stats['address_policy_count'] = {}
        for policy in self.model.policies:
            for addr in policy.get('srcaddr', []) + policy.get('dstaddr', []):
                self.relationship_stats['address_policy_count'][addr] = \
                    self.relationship_stats['address_policy_count'].get(addr, 0) + 1
        # Service Usage Analysis
        self.relationship_stats['service_policy_count'] = {}
        for policy in self.model.policies:
            for svc in policy.get('service', []):
                self.relationship_stats['service_policy_count'][svc] = \
                    self.relationship_stats['service_policy_count'].get(svc, 0) + 1
        # Group Nesting Analysis
        self.relationship_stats['address_group_depth'] = {}
        self.relationship_stats['service_group_depth'] = {}
        self._analyze_group_depth('address')
        self._analyze_group_depth('service')
        
        print("Analysis complete.")
    
    def _analyze_group_depth(self, group_type):
        """Analyze the nesting depth of address or service groups."""
        # Assuming this method correctly calculates depth based on the full model
        # No changes needed here unless we want depth of *used* groups only.
        
        group_dict = self.model.addr_groups if group_type == 'address' else self.model.svc_groups
        depth_dict = self.relationship_stats['address_group_depth'] if group_type == 'address' else self.relationship_stats['service_group_depth']

        memo = {}
        
        def calculate_depth(name, visited):
            if name in memo: return memo[name]
            if name in visited: return 0 # Cycle detected

            visited.add(name)
            
            current_group_members = group_dict.get(name)
            if not current_group_members: # Not a group or empty group
                 memo[name] = 0
                 return 0

            max_depth = 0
            for member in current_group_members:
                # Check if the member is itself a group of the same type
                member_is_group = member in group_dict
                if member_is_group:
                    depth = calculate_depth(member, visited.copy())
                    max_depth = max(max_depth, depth)
                # else: member is a base object (address/service), depth is 0 from here

            memo[name] = max_depth + 1
            return max_depth + 1

        # Calculate depth for each group in the model
        for group_name in group_dict:
             # Only calculate for potentially used groups? Or all? Let's do all for now.
             depth_dict[group_name] = calculate_depth(group_name, set())

    
    def _identify_unused_objects(self):
        """Identifies objects not present in the 'used' sets."""
        unused = {}
        unused['addresses'] = set(self.model.addresses.keys()) - self.used_addresses
        unused['addr_groups'] = set(self.model.addr_groups.keys()) - self.used_addr_groups
        unused['services'] = set(self.model.services.keys()) - self.used_services
        unused['svc_groups'] = set(self.model.svc_groups.keys()) - self.used_svc_groups
        unused['interfaces'] = set(self.model.interfaces.keys()) - self.used_interfaces
        unused['zones'] = set(self.model.zones.keys()) - self.used_zones
        unused['vips'] = set(self.model.vips.keys()) - self.used_vips
        unused['ippools'] = set(self.model.ippools.keys()) - self.used_ippools
        
        # Identify unused routes (index-based)
        all_route_indices = set(range(len(self.model.routes)))
        unused_route_indices = all_route_indices - self.used_routes
        unused['routes'] = [self.model.routes[i].get('name', f'Route Index {i}') for i in unused_route_indices] # Get names/IDs

        unused['phase1'] = set(self.model.phase1.keys()) - self.used_phase1
        unused['phase2'] = set(self.model.phase2.keys()) - self.used_phase2
        
        # Identify unused DHCP Servers (ID-based)
        all_dhcp_ids = {s.get('id') for s in self.model.dhcp_servers if s.get('id')}
        unused['dhcp_servers'] = all_dhcp_ids - self.used_dhcp_servers
        
        # Add other object types as needed
        return unused

    def generate_unused_report(self, output_file):
        """Generates a text report listing unused objects."""
        print("Generating unused objects report...")
        unused_objects = self._identify_unused_objects()
        report_file = f"{output_file}_unused.txt"
        total_unused = 0
        try:
            with open(report_file, 'w') as f:
                f.write("=== Unused Configuration Objects ===\n")
                f.write("(Objects not found to be referenced by enabled policies, routes, VPNs, etc.)\n\n")
                
                found_unused = False
                for obj_type, names in unused_objects.items():
                    # Sort names if it's a set or list of strings/numbers
                    sorted_names = []
                    if isinstance(names, (set, list)):
                        try:
                           sorted_names = sorted(list(names))
                        except TypeError: # Handle unorderable types if necessary
                           sorted_names = list(names)
                    
                    if sorted_names:
                        found_unused = True
                        f.write(f"--- Unused {obj_type.replace('_', ' ').title()} ({len(sorted_names)}) ---\n")
                        for name in sorted_names:
                            f.write(f"- {name}\n")
                        f.write("\n")
                        total_unused += len(sorted_names)
                
                if not found_unused:
                     f.write("No unused objects found in the analyzed categories.\n")

            print(f"Successfully generated unused objects report: {report_file}")
            return report_file # Return filename for reference
        except Exception as e:
            print(f"Error generating unused objects report: {e}")
            return None

    def generate_relationship_summary(self):
        """Generate a detailed summary of object relationships (based on full model)."""
        # Keep this summary based on the full model for now, as it provides context.
        # Could be modified later to only show stats for used objects.
        summary = []
        summary.append("=== Relationship Analysis Summary (Based on Full Configuration) ===")
        
        # Zone Analysis
        summary.append("\n=== Zone -> Interface Counts ===")
        # Sort zones by name for consistent output
        sorted_zones = sorted(self.relationship_stats['zone_interface_count'].items())
        for zone, count in sorted_zones:
            summary.append(f"Zone '{zone}': {count} interfaces")
            # Show interfaces, maybe mark used ones?
            interfaces = self.model.zones.get(zone, [])
            interfaces_str = ', '.join(f"{i}{'*' if i in self.used_interfaces else ''}" for i in interfaces)
            summary.append(f"  Interfaces: {interfaces_str} (* = Used in Diagram)")
        if not sorted_zones: summary.append("  (No zones defined)")

        # Policy Analysis
        summary.append("\n=== Policy Object Counts ===")
        sorted_policy_ids = sorted(self.relationship_stats['policy_address_count'].keys(), key=lambda x: int(x) if x.isdigit() else float('inf'))
        for policy_id in sorted_policy_ids:
            addr_counts = self.relationship_stats['policy_address_count'][policy_id]
            svc_count = self.relationship_stats['policy_service_count'][policy_id]
            policy_info = next((p for p in self.model.policies if p.get('id') == policy_id), None)
            status = policy_info.get('status', 'N/A') if policy_info else 'N/A'
            summary.append(f"Policy {policy_id} (Status: {status}):")
            summary.append(f"  Source Addresses: {addr_counts['src']}")
            summary.append(f"  Destination Addresses: {addr_counts['dst']}")
            summary.append(f"  Services: {svc_count}")
        if not sorted_policy_ids: summary.append("  (No policies defined)")
        
        # Interface Usage Analysis
        summary.append("\n=== Interface Policy Usage ===")
        sorted_interface_usage = sorted(self.relationship_stats['interface_policy_count'].items())
        for intf, count in sorted_interface_usage:
            used_marker = "*" if intf in self.used_interfaces else ""
            summary.append(f"Interface '{intf}'{used_marker}: Used in {count} policies")
        if not sorted_interface_usage: summary.append("  (No interfaces used in policies)")

        # Address Usage Analysis
        summary.append("\n=== Address/Group Policy Usage ===")
        sorted_address_usage = sorted(self.relationship_stats['address_policy_count'].items())
        for addr, count in sorted_address_usage:
            is_group = addr in self.model.addr_groups
            used_marker = "*" if (addr in self.used_addresses or addr in self.used_addr_groups) else ""
            type_label = "Group" if is_group else "Address"
            summary.append(f"{type_label} '{addr}'{used_marker}: Used in {count} policies")
        if not sorted_address_usage: summary.append("  (No addresses/groups used in policies)")
            
        # Service Usage Analysis
        summary.append("\n=== Service/Group Policy Usage ===")
        sorted_service_usage = sorted(self.relationship_stats['service_policy_count'].items())
        for svc, count in sorted_service_usage:
            is_group = svc in self.model.svc_groups
            used_marker = "*" if (svc in self.used_services or svc in self.used_svc_groups) else ""
            type_label = "Group" if is_group else "Service"
            summary.append(f"{type_label} '{svc}'{used_marker}: Used in {count} policies")
        if not sorted_service_usage: summary.append("  (No services/groups used in policies)")
            
        # Group Nesting Analysis
        summary.append("\n=== Group Nesting Analysis ===")
        summary.append("Address Groups (Max Depth):")
        sorted_addr_depth = sorted(self.relationship_stats['address_group_depth'].items())
        for group, depth in sorted_addr_depth:
             used_marker = "*" if group in self.used_addr_groups else ""
             summary.append(f"  {group}{used_marker}: Depth = {depth}")
        if not sorted_addr_depth: summary.append("  (No address groups defined)")
            
        summary.append("\nService Groups (Max Depth):")
        sorted_svc_depth = sorted(self.relationship_stats['service_group_depth'].items())
        for group, depth in sorted_svc_depth:
             used_marker = "*" if group in self.used_svc_groups else ""
             summary.append(f"  {group}{used_marker}: Depth = {depth}")
        if not sorted_svc_depth: summary.append("  (No service groups defined)")
            
        return '\n'.join(summary)
    
    def generate_diagram(self, output_file='network_topology'):
        """Generate the network diagram (used objects) and reports."""
        try:
            # 1. Analyze relationships and identify used objects
            self.analyze_relationships()
            
            # Reset processed nodes before drawing
            self.processed_nodes = set()

            # 2. Generate main configuration sections using filtered methods
            # These will build self.graph with only used nodes/edges
            print("Generating diagram components (used objects only)...")
            self.generate_network_hierarchy()
            self.generate_security_configuration()
            self.generate_nat_configuration()
            
            # 3. Generate relationship summary (based on full model)
            print("Generating relationship summary...")
            summary = self.generate_relationship_summary()
            summary_file = f"{output_file}_relationships.txt"
            try:
                with open(summary_file, 'w') as f:
                    f.write(summary)
                print(f"Successfully generated relationship summary: {summary_file}")
            except Exception as e:
                print(f"Error writing relationship summary: {e}")

            # 4. Generate the unused objects report
            unused_report_file = self.generate_unused_report(output_file) # Already prints success/error

            # 5. Set rendering options based on graph complexity (of the *drawn* graph)
            num_nodes = len(self.processed_nodes)
            print(f"Diagram contains {num_nodes} nodes representing used objects.")
            
            # Adjust graph attributes based on size
            if num_nodes > 150: # Increased threshold
                self.graph.attr(dpi='72', size='16,22', nodesep='0.2', ranksep='0.3', fontsize='7')
            elif num_nodes > 75: # Increased threshold
                self.graph.attr(dpi='96', size='14,20', nodesep='0.3', ranksep='0.4', fontsize='8')
            elif num_nodes > 30:
                self.graph.attr(dpi='120', size='11,16', nodesep='0.4', ranksep='0.5', fontsize='9')
            else: # Smaller graphs can have higher detail
                self.graph.attr(dpi='150', size='8.5,11', nodesep='0.5', ranksep='0.6', fontsize='10')
            
            # 6. Render the diagram
            print("Rendering diagrams (PDF and PNG)...")
            engines = ['dot', 'fdp', 'neato', 'sfdp'] # Added sfdp for potentially large graphs
            success = False
            last_engine = 'dot' # Default
            
            for engine in engines:
                try:
                    self.graph.engine = engine
                    last_engine = engine
                    # Generate PDF
                    pdf_file = f"{output_file}.pdf"
                    self.graph.render(output_file, view=False, format='pdf', cleanup=True)
                    # Generate PNG
                    png_file = f"{output_file}.png"
                    # Slightly higher DPI for PNG if graph isn't huge
                    png_dpi = '144' if num_nodes < 150 else '96'
                    self.graph.attr(dpi=png_dpi)
                    self.graph.render(output_file, view=False, format='png', cleanup=True)
                    success = True
                    print(f"Successfully rendered diagrams using '{engine}' engine.")
                    break # Stop trying engines on success
                except Exception as e:
                    print(f"Layout engine '{engine}' failed: {str(e)}")
                    # Don't cleanup if engine failed, might leave intermediate files
                    if engine == engines[-1]: # If it's the last engine, report failure
                        print(f"All layout engines failed. Diagram rendering incomplete.")
                    else:
                        print("Trying next layout engine...")
                    continue
            
            if not success:
                # Attempt to save the dot file even if rendering fails
                dot_file = f"{output_file}.gv"
                try:
                     self.graph.save(dot_file)
                     print(f"Saved Graphviz definition file: {dot_file}")
                     print("You can try rendering it manually using: dot -Tpdf {dot_file} -o {output_file}.pdf")
                except Exception as save_e:
                     print(f"Could not save Graphviz definition file: {save_e}")
                raise Exception("All layout engines failed to render the diagram.")

            # Final summary print
            print(f"\n--- Generation Complete ---")
            print(f"Used layout engine: {last_engine}")
            print(f"Output Files:")
            print(f"- {pdf_file} (Diagram of used objects)")
            print(f"- {png_file} (Diagram of used objects)")
            print(f"- {summary_file} (Relationship analysis - full config)")
            if unused_report_file:
                print(f"- {unused_report_file} (List of unused objects)")
            
        except Exception as e:
            print(f"\n--- Error During Diagram Generation ---")
            print(f"{e}")
            import traceback
            traceback.print_exc() # Print full traceback for debugging
            print("\nPlease ensure Graphviz (dot, fdp, etc.) is installed and in your system's PATH.")
            print("If the graph is very large, layout engines may require significant memory and time.")

    # --- Network Path Tracing (New Functionality) ---

    def _ip_in_subnet(self, ip_str, subnet_str):
        """Check if an IP address string belongs to a subnet string."""
        try:
            ip = ipaddress.ip_address(ip_str)
            net = ipaddress.ip_network(subnet_str, strict=False)
            return ip in net
        except ValueError:
            return False # Invalid IP or subnet format

    def _resolve_address_object(self, name, visited=None):
        """Recursively resolve an address or group name to a set of IP networks/addresses."""
        if visited is None:
            visited = set()
        if name in visited:
            return set() # Avoid cycles

        visited.add(name)
        resolved_subnets = set()

        if name in self.model.addresses:
            addr_data = self.model.addresses[name]
            addr_type = addr_data.get('type', 'subnet')
            subnet_val = addr_data.get('subnet', '') # Contains IP/Mask, FQDN, Range, etc.
            # Handle different address types appropriately
            if addr_type in ['ipmask', 'subnet'] and subnet_val:
                try:
                    resolved_subnets.add(ipaddress.ip_network(subnet_val, strict=False))
                except ValueError:
                    pass # Ignore invalid subnets
            elif addr_type == 'iprange' and '-' in subnet_val:
                 try:
                     start_ip, end_ip = subnet_val.split('-')
                     resolved_subnets.update(ipaddress.summarize_address_range(
                         ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip)
                     ))
                 except ValueError:
                     pass # Ignore invalid ranges
            # FQDN, Geography, Wildcard, Dynamic etc. are harder to resolve statically to IPs
            # For path tracing, we might need to assume 'any' or require specific IP inputs

        elif name in self.model.addr_groups:
            for member in self.model.addr_groups.get(name, []):
                resolved_subnets.update(self._resolve_address_object(member, visited.copy()))

        return resolved_subnets

    def _resolve_service_object(self, name, visited=None):
        """Recursively resolve a service or group name to a set of (protocol, port_range) tuples."""
        if visited is None:
            visited = set()
        if name in visited:
            return set() # Avoid cycles

        visited.add(name)
        resolved_services = set()

        if name in self.model.services:
             svc_data = self.model.services[name]
             protocol = svc_data.get('protocol', '').upper()
             port_str = svc_data.get('port', '') # Can be range '1-1024', single '80', ICMP info
             # TODO: Parse port_str into a more usable format (e.g., start/end port)
             if protocol in ['TCP', 'UDP', 'SCTP']:
                 resolved_services.add((protocol, port_str))
             elif protocol == 'ICMP':
                 resolved_services.add(('ICMP', port_str)) # Store ICMP type/code info
             elif protocol == 'IP':
                 resolved_services.add(('IP', port_str)) # Store protocol number
             else: # Any/Other
                 resolved_services.add(('ANY', 'ANY'))


        elif name in self.model.svc_groups:
            for member in self.model.svc_groups.get(name, []):
                resolved_services.update(self._resolve_service_object(member, visited.copy()))

        return resolved_services


    def _find_source_interface(self, source_ip_str):
        """Find the interface connected to the source IP."""
        source_ip = ipaddress.ip_address(source_ip_str)
        # Check interface IPs/subnets
        for name, iface_data in self.model.interfaces.items():
            ip_subnet = iface_data.get('ip', '') # e.g., "192.168.1.1/24"
            if ip_subnet:
                try:
                    if_net = ipaddress.ip_network(ip_subnet, strict=False)
                    # Check if source IP is within the interface's network
                    if source_ip in if_net:
                         print(f"DEBUG: Source IP {source_ip_str} matches interface {name} ({ip_subnet})")
                         return name, iface_data
                except ValueError:
                    continue # Skip invalid interface IPs
        print(f"DEBUG: No direct interface match found for source IP {source_ip_str}")
        return None, None # Not found on any directly configured interface subnet


    def _find_matching_route(self, dest_ip_str, current_interface=None):
        """
        Find the best matching static route for the destination IP.
        Considers longest prefix match. Returns route dict and next hop IP.
        (Currently only considers static routes)
        """
        dest_ip = ipaddress.ip_address(dest_ip_str)
        best_match_route = None
        longest_prefix = -1

        print(f"DEBUG: Route lookup for {dest_ip_str}")
        for idx, route in enumerate(self.model.routes):
            if route.get('status', 'enable') != 'enable':
                 # print(f"DEBUG: Skipping disabled route {idx}")
                 continue

            dst_subnet_str = route.get('dst', '') # e.g., "0.0.0.0/0" or "10.0.0.0/8"
            if not dst_subnet_str:
                 # print(f"DEBUG: Skipping route {idx} with no destination")
                 continue

            try:
                route_net = ipaddress.ip_network(dst_subnet_str, strict=False)
                if dest_ip in route_net:
                    print(f"DEBUG: Route {idx} ({dst_subnet_str}) is a potential match for {dest_ip_str}")
                    if route_net.prefixlen > longest_prefix:
                        longest_prefix = route_net.prefixlen
                        best_match_route = route
                        print(f"DEBUG: New best match: Route {idx} (prefix {longest_prefix})")
            except ValueError:
                print(f"DEBUG: Skipping route {idx} with invalid destination subnet: {dst_subnet_str}")
                continue # Skip invalid routes

        if best_match_route:
             next_hop_ip = best_match_route.get('gateway', '')
             egress_device = best_match_route.get('device', '')
             print(f"DEBUG: Best route found: ID {best_match_route.get('name', idx)}, Dest {best_match_route.get('dst')}, Via {next_hop_ip if next_hop_ip else 'connected'}, Device {egress_device}")
             # If gateway is empty, it's likely a directly connected route
             return best_match_route, next_hop_ip if next_hop_ip else None
        else:
            # If no static route matches, check if destination is on a directly connected network
            # This needs refinement - which connected network? Check against current_interface?
            print(f"DEBUG: No specific static route found for {dest_ip_str}. Checking connected.")
            # Placeholder: Need logic to check connected networks based on current location in trace
            return None, None


    def _check_firewall_policy(self, src_ip, dst_ip, dst_port, protocol, src_intf_name, dst_intf_name):
        """
        Check firewall policies for allowed traffic.
        Returns the matching policy dict if allowed, None otherwise.
        Expands address/service groups for matching.
        Checks zones based on interfaces.
        """
        print(f"DEBUG: Checking firewall policy: {src_ip} -> {dst_ip}:{dst_port}/{protocol} ({src_intf_name} -> {dst_intf_name})")
        # Find source and destination zones
        src_zone = None
        dst_zone = None
        for z_name, z_data in self.model.zones.items():
             if src_intf_name in z_data.get('interface', []):
                 src_zone = z_name
             if dst_intf_name in z_data.get('interface', []):
                 dst_zone = z_name
        print(f"DEBUG: Source Zone: {src_zone}, Dest Zone: {dst_zone}")

        for policy in self.model.policies:
            policy_id = policy.get('id', 'N/A')
            if policy.get('status', 'enable') != 'enable':
                # print(f"DEBUG: Skipping disabled policy {policy_id}")
                continue

            # 1. Match Interfaces/Zones
            src_intf_match = False
            policy_src_intfs = policy.get('srcintf', [])
            if not policy_src_intfs: continue # Policy must have srcintf
            # Check direct interface match OR zone match
            if src_intf_name in policy_src_intfs or (src_zone and src_zone in policy_src_intfs):
                 src_intf_match = True

            dst_intf_match = False
            policy_dst_intfs = policy.get('dstintf', [])
            if not policy_dst_intfs: continue # Policy must have dstintf
            if dst_intf_name in policy_dst_intfs or (dst_zone and dst_zone in policy_dst_intfs):
                 dst_intf_match = True

            if not (src_intf_match and dst_intf_match):
                # print(f"DEBUG: Policy {policy_id} interface mismatch.")
                continue
            print(f"DEBUG: Policy {policy_id} interface match OK.")

            # 2. Match Source Address
            src_addr_match = False
            policy_src_addrs = policy.get('srcaddr', ['all']) # Default to 'all' if empty? Check FortiOS behavior
            if 'all' in policy_src_addrs:
                 src_addr_match = True
            else:
                 for addr_name in policy_src_addrs:
                     resolved_nets = self._resolve_address_object(addr_name)
                     for net in resolved_nets:
                          if ipaddress.ip_address(src_ip) in net:
                              src_addr_match = True
                              break
                     if src_addr_match: break
            if not src_addr_match:
                # print(f"DEBUG: Policy {policy_id} src addr mismatch.")
                continue
            print(f"DEBUG: Policy {policy_id} src addr match OK.")

            # 3. Match Destination Address (including VIPs)
            dst_addr_match = False
            policy_dst_addrs = policy.get('dstaddr', ['all'])
            if 'all' in policy_dst_addrs:
                 dst_addr_match = True
            else:
                for addr_name in policy_dst_addrs:
                    # Check if addr_name is a VIP first
                    if addr_name in self.model.vips:
                         vip_data = self.model.vips[addr_name]
                         vip_ext_ip = vip_data.get('extip', '')
                         # Simple IP match for now, needs port/protocol check later
                         if vip_ext_ip == dst_ip:
                              dst_addr_match = True
                              break
                    else: # Check regular addresses/groups
                        resolved_nets = self._resolve_address_object(addr_name)
                        for net in resolved_nets:
                            if ipaddress.ip_address(dst_ip) in net:
                                dst_addr_match = True
                                break
                    if dst_addr_match: break
            if not dst_addr_match:
                 # print(f"DEBUG: Policy {policy_id} dst addr mismatch.")
                 continue
            print(f"DEBUG: Policy {policy_id} dst addr match OK.")

            # 4. Match Service
            svc_match = False
            policy_svcs = policy.get('service', ['ALL'])
            if 'ALL' in policy_svcs: # Check for explicit 'ALL' keyword
                 svc_match = True
            else:
                # Convert input port to integer for comparison if possible
                try:
                    req_port = int(dst_port)
                except ValueError:
                    req_port = None # Handle non-numeric ports/ICMP later

                for svc_name in policy_svcs:
                     resolved_svcs = self._resolve_service_object(svc_name)
                     for svc_proto, svc_port_range in resolved_svcs:
                          # Protocol Match
                          proto_match = False
                          if svc_proto == 'ANY' or svc_proto == protocol.upper() or \
                             (svc_proto == 'TCP/UDP/SCTP' and protocol.upper() in ['TCP','UDP','SCTP']):
                             proto_match = True

                          if not proto_match: continue

                          # Port Match (if applicable)
                          port_match = False
                          if svc_proto in ['TCP', 'UDP', 'SCTP']:
                               if req_port is None: continue # Cannot match non-numeric port
                               # Parse svc_port_range (e.g., "80", "1024-2000")
                               try:
                                   if '-' in svc_port_range:
                                       start_p, end_p = map(int, svc_port_range.split('-'))
                                       if start_p <= req_port <= end_p: port_match = True
                                   elif svc_port_range: # Single port
                                       if req_port == int(svc_port_range): port_match = True
                               except ValueError:
                                   pass # Ignore invalid port ranges
                          elif svc_proto in ['ICMP', 'IP', 'ANY']:
                               port_match = True # No port matching needed for these (or handled by protocol)

                          if proto_match and port_match:
                              svc_match = True
                              break
                     if svc_match: break
            if not svc_match:
                # print(f"DEBUG: Policy {policy_id} service mismatch.")
                continue
            print(f"DEBUG: Policy {policy_id} service match OK.")

            # 5. Check Action
            action = policy.get('action', 'deny') # Default deny?
            if action == 'accept':
                print(f"DEBUG: Policy {policy_id} ACCEPTED.")
                return policy # Return the accepting policy
            else:
                 print(f"DEBUG: Policy {policy_id} DENIED (Action: {action}).")
                 return None # Explicit deny stops further policy checks for this path segment

        print("DEBUG: No matching allow policy found.")
        return None # No policy matched or all matched were deny


    def _apply_nat(self, policy, original_src_ip, original_dst_ip, original_dst_port, protocol):
        """
        Applies NAT based on the matched policy (VIP or IP Pool).
        Returns (new_src_ip, new_dst_ip, new_dst_port).
        """
        new_src_ip = original_src_ip
        new_dst_ip = original_dst_ip
        new_dst_port = original_dst_port

        # 1. Destination NAT (VIP)
        # Check if the original destination matched a VIP used in the policy's dstaddr
        matched_vip_name = None
        for addr_name in policy.get('dstaddr', []):
             if addr_name in self.model.vips:
                 vip_data = self.model.vips[addr_name]
                 vip_ext_ip = vip_data.get('extip', '')
                 if vip_ext_ip == original_dst_ip:
                      # TODO: Add port/protocol matching for VIPs
                      matched_vip_name = addr_name
                      break

        if matched_vip_name:
            vip_data = self.model.vips[matched_vip_name]
            vip_mapped_ip = vip_data.get('mappedip', '')
            if vip_mapped_ip:
                 new_dst_ip = vip_mapped_ip # Translate destination IP
                 print(f"DEBUG: DNAT (VIP {matched_vip_name}): {original_dst_ip} -> {new_dst_ip}")
                 # Apply port forwarding if enabled
                 if vip_data.get('portforward') == 'enable':
                      vip_proto = vip_data.get('protocol', '').upper()
                      vip_ext_port = vip_data.get('extport', '')
                      vip_mapped_port = vip_data.get('mappedport', '')
                      # Check if protocol and external port match the flow
                      if (vip_proto == protocol.upper() or vip_proto == 'ANY') and vip_ext_port == str(original_dst_port):
                           new_dst_port = vip_mapped_port # Translate destination port
                           print(f"DEBUG: DNAT Port Fwd: {original_dst_port} -> {new_dst_port}")

        # 2. Source NAT (IP Pool or Interface IP)
        if policy.get('nat', 'disable') == 'enable':
            if policy.get('ippool', 'disable') == 'enable':
                pool_name = policy.get('poolname', '')
                if pool_name and pool_name in self.model.ippools:
                    pool_data = self.model.ippools[pool_name]
                    # Simple NAT: Use start IP of the pool. Real NAT is more complex (port mapping etc)
                    # For tracing, knowing *that* SNAT happens might be enough.
                    snat_ip = pool_data.get('startip', '')
                    if snat_ip:
                         new_src_ip = snat_ip
                         print(f"DEBUG: SNAT (Pool {pool_name}): {original_src_ip} -> {new_src_ip}")
                else:
                     print(f"DEBUG: SNAT enabled but pool '{pool_name}' not found or invalid.")
            else:
                # Fallback to using egress interface IP for NAT (if not pool)
                # Need the egress interface IP from the route lookup step
                # This requires passing egress interface info to _apply_nat
                # Placeholder:
                # egress_intf_ip = get_egress_intf_ip(...)
                # new_src_ip = egress_intf_ip
                print(f"DEBUG: SNAT (Egress Interface IP - placeholder): {original_src_ip} -> EgressIP")
                pass # Needs egress interface IP

        return new_src_ip, new_dst_ip, new_dst_port


    def trace_network_path(self, source_ip, dest_ip, dest_port, protocol='tcp', max_hops=30):
        """
        Traces a potential network path based on static routes and firewall policies.

        Args:
            source_ip (str): The source IP address.
            dest_ip (str): The destination IP address.
            dest_port (int or str): The destination port number (or ICMP type/code).
            protocol (str): The protocol (e.g., 'tcp', 'udp', 'icmp').
            max_hops (int): Maximum number of routing hops to trace.

        Returns:
            list: A list of dictionaries, each representing a hop in the path,
                  or an empty list if the path is blocked or destination unreachable.
                  Returns None on error (e.g., invalid input).
            str: A status message indicating success, blocked reason, or error.
        """
        path = []
        current_ip = source_ip
        current_port = None # Source port isn't tracked in this simplified trace
        current_dest_ip = dest_ip
        current_dest_port = dest_port
        current_protocol = protocol.lower()

        try:
            ipaddress.ip_address(source_ip)
            ipaddress.ip_address(dest_ip)
        except ValueError as e:
            return None, f"Error: Invalid source or destination IP address: {e}"

        # Find initial interface
        current_intf_name, current_intf_data = self._find_source_interface(source_ip)
        if not current_intf_name:
             return path, f"Blocked: Source IP {source_ip} not found on any interface subnet."

        print(f"--- Starting Path Trace ---")
        print(f"From: {source_ip} To: {dest_ip}:{dest_port}/{protocol}")
        print(f"Initial Interface: {current_intf_name}")
        path.append({
            "hop": 0,
            "type": "Source",
            "interface": current_intf_name,
            "ip": source_ip,
            "details": "Trace initiated."
        })


        for hop_count in range(1, max_hops + 1):
            print(f"\n--- Hop {hop_count} ---")
            print(f"Current State: Src={current_ip}, Dst={current_dest_ip}:{current_dest_port}/{current_protocol}, Intf={current_intf_name}")

            # 1. Route Lookup for the *current* destination IP
            route, next_hop_gw_ip = self._find_matching_route(current_dest_ip, current_intf_name)

            if not route:
                # Check if destination is directly connected to the *current* interface
                if current_intf_data and self._ip_in_subnet(current_dest_ip, current_intf_data.get('ip','')):
                     print(f"DEBUG: Destination {current_dest_ip} is directly connected to {current_intf_name}. Final firewall check needed.")
                     next_hop_intf_name = current_intf_name # Destination is on the same interface segment
                     # Perform a final firewall check (policy from current_intf to itself? Check intrazone?)
                     # This logic needs refinement - how are policies applied for local subnet traffic?
                     # Assuming a check against policies sourced from current_intf is still needed.
                     final_policy = self._check_firewall_policy(
                         current_ip, current_dest_ip, current_dest_port, current_protocol,
                         current_intf_name, next_hop_intf_name
                     )
                     if final_policy:
                          path.append({
                              "hop": hop_count,
                              "type": "Firewall",
                              "policy_id": final_policy.get('id'),
                              "action": "Allow",
                              "details": f"Traffic allowed by policy {final_policy.get('id')} to directly connected destination."
                          })
                          path.append({
                              "hop": hop_count + 1,
                              "type": "Destination",
                              "interface": next_hop_intf_name,
                              "ip": current_dest_ip,
                              "details": "Destination reached (directly connected)."
                          })
                          return path, f"Success: Destination {dest_ip} reached via {current_intf_name}."
                     else:
                          path.append({
                              "hop": hop_count,
                              "type": "Firewall",
                              "action": "Block",
                              "details": f"Traffic to directly connected destination {current_dest_ip} blocked by policy."
                          })
                          return path, f"Blocked: Firewall denied traffic to directly connected {dest_ip} on {current_intf_name}."
                else:
                     path.append({
                         "hop": hop_count,
                         "type": "Routing",
                         "action": "Block",
                         "details": f"No route found for destination {current_dest_ip} from interface {current_intf_name}."
                     })
                     return path, f"Blocked: No route to {current_dest_ip}."

            # Determine Egress Interface from Route
            egress_intf_name = route.get('device', '')
            if not egress_intf_name or egress_intf_name not in self.model.interfaces:
                path.append({
                    "hop": hop_count,
                    "type": "Routing",
                    "action": "Block",
                    "details": f"Route {route.get('name', 'N/A')} has invalid/missing egress interface '{egress_intf_name}'."
                })
                return path, f"Blocked: Invalid egress interface '{egress_intf_name}' in route."

            print(f"DEBUG: Route points to Egress Interface: {egress_intf_name}")
            path.append({
                "hop": hop_count,
                "type": "Routing",
                "route_id": route.get('name', 'N/A'),
                "destination": route.get('dst'),
                "gateway": next_hop_gw_ip if next_hop_gw_ip else "Directly Connected",
                "interface": egress_intf_name,
                "details": f"Traffic routed via {egress_intf_name}."
            })

            # 2. Firewall Check between current_intf_name and egress_intf_name
            policy = self._check_firewall_policy(
                current_ip, current_dest_ip, current_dest_port, current_protocol,
                current_intf_name, egress_intf_name
            )

            if not policy:
                path.append({
                    "hop": hop_count,
                    "type": "Firewall",
                    "action": "Block",
                    "source_intf": current_intf_name,
                    "dest_intf": egress_intf_name,
                    "details": f"Traffic blocked by firewall policy between {current_intf_name} and {egress_intf_name}."
                })
                return path, f"Blocked: Firewall denied traffic from {current_intf_name} to {egress_intf_name}."

            print(f"DEBUG: Firewall policy {policy.get('id')} allows traffic.")
            path.append({
                "hop": hop_count,
                "type": "Firewall",
                "policy_id": policy.get('id'),
                "action": "Allow",
                "source_intf": current_intf_name,
                "dest_intf": egress_intf_name,
                "details": f"Traffic allowed by policy {policy.get('id')}."
            })

            # 3. Apply NAT based on the policy
            # Store original IPs before potential NAT for the next hop's source
            pre_nat_src_ip = current_ip
            pre_nat_dst_ip = current_dest_ip

            nat_src_ip, nat_dst_ip, nat_dst_port = self._apply_nat(
                policy, current_ip, current_dest_ip, current_dest_port, current_protocol
            )

            if nat_src_ip != current_ip or nat_dst_ip != current_dest_ip or nat_dst_port != current_dest_port:
                 nat_details = []
                 if nat_src_ip != current_ip: nat_details.append(f"SNAT: {current_ip} -> {nat_src_ip}")
                 if nat_dst_ip != current_dest_ip: nat_details.append(f"DNAT: {current_dest_ip} -> {nat_dst_ip}")
                 if nat_dst_port != current_dest_port: nat_details.append(f"DNAT Port: {current_dest_port} -> {nat_dst_port}")
                 print(f"DEBUG: NAT Applied: {', '.join(nat_details)}")
                 path.append({
                     "hop": hop_count,
                     "type": "NAT",
                     "policy_id": policy.get('id'),
                     "details": ", ".join(nat_details)
                 })
                 # Update current state for the *next* hop
                 current_ip = nat_src_ip
                 current_dest_ip = nat_dst_ip
                 current_dest_port = nat_dst_port
            else:
                 print("DEBUG: No NAT applied by policy.")


            # 4. Prepare for next hop
            # The "source" IP for the next hop's check is the post-SNAT IP
            # The "destination" IP for the next hop's check is the post-DNAT IP
            # The current interface becomes the egress interface of this hop
            current_intf_name = egress_intf_name
            current_intf_data = self.model.interfaces.get(current_intf_name)

            # Check if the *new* destination IP is on the current (egress) interface's subnet
            if current_intf_data and self._ip_in_subnet(current_dest_ip, current_intf_data.get('ip', '')):
                 print(f"DEBUG: Destination {current_dest_ip} reached after routing/NAT on interface {current_intf_name}.")
                 path.append({
                     "hop": hop_count + 1,
                     "type": "Destination",
                     "interface": current_intf_name,
                     "ip": current_dest_ip, # The potentially NAT-ted destination IP
                     "details": "Destination reached."
                 })
                 return path, f"Success: Destination {dest_ip} reached (landed on {current_intf_name})."

            # If the next hop is via a gateway, the source IP for the *next* hop's perspective
            # is effectively the NATted source IP leaving the *current* egress interface.
            # The routing lookup will happen again based on the (potentially NATted) destination.

        # Max hops reached
        path.append({
            "hop": max_hops + 1,
            "type": "Trace Limit",
            "action": "Block",
            "details": f"Maximum hop count ({max_hops}) reached."
        })
        return path, f"Blocked: Maximum hop count ({max_hops}) reached."

    # --- End Network Path Tracing ---

    # --- Connectivity Tree Generation ---

    def _get_interface_policy_refs(self, interface_name):
        """Find policy IDs referencing a specific interface directly or via its zone."""
        refs = set()
        zone_name = None
        # Find the zone this interface belongs to
        for z_name, z_data in self.model.zones.items():
            if interface_name in z_data.get('interface', []):
                zone_name = z_name
                break

        for policy in self.model.policies:
            policy_id = policy.get('id', 'N/A')
            src_intfs = policy.get('srcintf', [])
            dst_intfs = policy.get('dstintf', [])

            # Check if interface or its zone is in src or dst
            if interface_name in src_intfs or (zone_name and zone_name in src_intfs) or \
               interface_name in dst_intfs or (zone_name and zone_name in dst_intfs):
               refs.add(policy_id)
        return sorted(list(refs), key=lambda x: int(x) if x.isdigit() else float('inf'))

    def generate_connectivity_tree(self):
        """Generates an enhanced ASCII tree summarizing network connectivity."""
        tree = []
        tree.append("VDOM: root") # Assuming root VDOM for now

        interfaces_in_zones = set()
        all_interfaces = sorted(self.model.interfaces.keys())
        sdwan_members = {m.get('interface') for m in self.model.sd_wan.get('members',[])} # Get SD-WAN interface names

        # Pre-calculate routes, VPNs, VIPs per interface
        routes_by_interface = {}
        for idx, route in enumerate(self.model.routes):
            device = route.get('device')
            status = route.get('status', 'enable')
            if device and status == 'enable':
                 if device not in routes_by_interface: routes_by_interface[device] = []
                 routes_by_interface[device].append(route)

        vpns_by_interface = {}
        for p1_name, p1_data in self.model.phase1.items():
             iface = p1_data.get('interface')
             status = p1_data.get('status', 'enable')
             if iface and status == 'enable':
                 if iface not in vpns_by_interface: vpns_by_interface[iface] = []
                 vpns_by_interface[iface].append(p1_name)

        vips_by_interface = {}
        for vip_name, vip_data in self.model.vips.items():
            iface = vip_data.get('interface') # VIPs can be bound to 'any'
            if iface and iface != 'any': # Only show if bound to specific interface
                if iface not in vips_by_interface: vips_by_interface[iface] = []
                vips_by_interface[iface].append(vip_name)

        def format_interface_details(intf_name, indent_prefix, is_last_in_list):
            iface_data = self.model.interfaces.get(intf_name, {})
            ip_cidr = iface_data.get('ip', 'N/A')
            alias = iface_data.get('alias', '')
            sdwan_marker = " (SD-WAN)" if intf_name in sdwan_members else ""

            details = []
            # Interface line
            intf_line_prefix = f"{indent_prefix}├──" if not is_last_in_list else f"{indent_prefix}└──"
            details.append(f"{intf_line_prefix} Interface: {intf_name}{sdwan_marker}{f' ({alias})' if alias else ''}")

            # Calculate next level indent
            sub_indent_prefix = f"{indent_prefix}│   " if not is_last_in_list else f"{indent_prefix}    "

            # Sub-items (IP, Policies, Routes, VPNs, VIPs)
            sub_items = []
            # Directly Connected Subnet
            direct_subnet_str = "N/A"
            if ip_cidr != 'N/A':
                 try:
                     net = ipaddress.ip_network(ip_cidr, strict=False)
                     direct_subnet_str = str(net)
                     sub_items.append(("IP / Subnet", f"{ip_cidr} [{direct_subnet_str}]"))
                 except ValueError:
                     sub_items.append(("IP", f"{ip_cidr} [Invalid Format]"))
            else:
                 sub_items.append(("IP", "N/A"))

            # Policies
            policy_refs = self._get_interface_policy_refs(intf_name)
            if policy_refs:
                 sub_items.append(("Policies", f"[{ ', '.join(policy_refs) }]"))

            # Routes
            routes = routes_by_interface.get(intf_name, [])
            if routes:
                 route_destinations = [f"{r.get('dst', 'N/A')} -> {r.get('gateway', 'Direct')} (ID:{r.get('name', '?')})" for r in routes]
                 sub_items.append(("Static Routes Out", "; ".join(route_destinations)))

            # VPNs
            vpns = vpns_by_interface.get(intf_name, [])
            if vpns:
                 sub_items.append(("VPN Tunnels (P1)", f"[{ ', '.join(sorted(vpns)) }]"))

            # VIPs
            vips = vips_by_interface.get(intf_name, [])
            if vips:
                 sub_items.append(("Virtual IPs Hosted", f"[{ ', '.join(sorted(vips)) }]"))

            # Format sub-items
            for i, (label, value) in enumerate(sub_items):
                 sub_prefix = f"{sub_indent_prefix}├──" if i != len(sub_items) - 1 else f"{sub_indent_prefix}└──"
                 details.append(f"{sub_prefix} {label}: {value}")

            return "\n".join(details)


        # 1. Process Zones and their Interfaces
        sorted_zone_names = sorted(self.model.zones.keys())
        has_unassigned = any(intf not in interfaces_in_zones for intf in all_interfaces for zone_interfaces in self.model.zones.values() for intf in zone_interfaces.get('interface',[]))

        zone_section_prefix = "├──" if has_unassigned or routes_by_interface else "└──"
        if sorted_zone_names:
             tree.append(f"{zone_section_prefix} Zones")
             zone_indent = "│   " if has_unassigned or routes_by_interface else "    "
             for i, zone_name in enumerate(sorted_zone_names):
                 is_last_zone = (i == len(sorted_zone_names) - 1)
                 zone_prefix = f"{zone_indent}├──" if not is_last_zone else f"{zone_indent}└──"
                 tree.append(f"{zone_prefix} Zone: {zone_name}")

                 zone_interfaces = sorted(self.model.zones[zone_name].get('interface', []))
                 interface_indent = f"{zone_indent}│   " if not is_last_zone else f"{zone_indent}    "

                 for j, intf_name in enumerate(zone_interfaces):
                     interfaces_in_zones.add(intf_name)
                     is_last_intf = (j == len(zone_interfaces) - 1)
                     tree.append(format_interface_details(intf_name, interface_indent, is_last_intf))

        # 2. Process Interfaces NOT in any Zone
        unassigned_interfaces_names = sorted([name for name in all_interfaces if name not in interfaces_in_zones])
        unassigned_section_prefix = "├──" if routes_by_interface else "└──"
        if unassigned_interfaces_names:
             tree.append(f"{unassigned_section_prefix} Interfaces (No Zone)")
             interface_indent = "│   " if routes_by_interface else "    "
             for i, intf_name in enumerate(unassigned_interfaces_names):
                 is_last_intf = (i == len(unassigned_interfaces_names) - 1)
                 tree.append(format_interface_details(intf_name, interface_indent, is_last_intf))

        # Removed separate static route section as it's integrated above.

        return "\n".join(tree)

    # --- End Connectivity Tree Generation ---

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

class FortiParser:
    """Parses a FortiGate CLI export into a ConfigModel."""
    SECTION_RE = re.compile(r'^config\s+(.+)$') # Removed extra backslash before \s
    # Improved regex for 'edit' command: handles quoted/unquoted names and trailing spaces
    EDIT_RE    = re.compile(r'^edit\s+(?:"([^"]+)"|(\S+))\s*$', re.IGNORECASE)
    SET_RE     = re.compile(r'^set\s+(\S+)\s+(.+)$')
    NEXT_RE    = re.compile(r'^next$')
    END_RE     = re.compile(r'^end$')

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
        self.model = ConfigModel()

    def parse(self):
        """Parse the config file and return a ConfigModel."""
        self.i = 0
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                self.i += 1
                continue
                
            # Check for special VDOM or global configurations
            if self.VDOM_CONFIG_RE.match(line):
                print(f"DEBUG: Found VDOM config at line {self.i+1}")
                self._handle_vdom_config()
                self.model.has_vdoms = True
                continue
                
            if self.GLOBAL_CONFIG_RE.match(line):
                print(f"DEBUG: Found global config at line {self.i+1}")
                self._handle_global_config()
                continue
                
            # Regular section handling
            m = self.SECTION_RE.match(line)
            if m:
                sec_raw = m.group(1).lower()
                # Replace space and hyphen with underscore for handler lookup
                sec = sec_raw.replace(' ', '_').replace('-', '_')

                # --- Use Alias Map ---
                handler_name = self.SECTION_ALIASES.get(sec)
                if not handler_name:
                    # If not in aliases, construct the default handler name
                    handler_name = f"_handle_{sec}"
                # --- End Alias Map ---

                print(f"DEBUG: Matched section '{sec_raw}' (Handler: {handler_name}) at line {self.i+1}. Current VDOM: {self.current_vdom}") # DEBUG
                handler = getattr(self, handler_name, None) # Use the determined handler_name

                if handler:
                    print(f"DEBUG: Found handler '{handler_name}'. Entering...") # DEBUG
                    try:
                        handler()
                        # Handler is responsible for consuming the 'end' line
                        print(f"DEBUG: Successfully exited handler '{handler_name}'. self.i is now {self.i}") # DEBUG
                    except Exception as e:
                        print(f"Error processing section '{sec_raw}' with handler '{handler_name}': {e}", file=sys.stderr)
                        import traceback
                        traceback.print_exc(file=sys.stderr)
                        print(f"Attempting to skip block for section '{sec_raw}'...")
                        try:
                             self._skip_block() # Attempt to recover by skipping
                             print(f"DEBUG: Successfully skipped block. self.i is now {self.i}") # DEBUG
                        except Exception as skip_e:
                             print(f"Error trying to skip block after handler error: {skip_e}. Aborting.")
                             raise # Re-raise original error if skip fails catastrophically
                else:
                    # Use generic handler for unrecognized sections
                    print(f"Warning: Using generic handler for unrecognized section: {sec_raw} (Normalized: {sec}) at line {self.i+1}", file=sys.stderr)
                    self._handle_generic_section(sec_raw, sec)
            else:
                # If the line is NOT a section start, AND not empty/comment
                print(f"DEBUG: Skipping non-section line {self.i+1}: {line[:80]}...") # DEBUG
                self.i += 1

        print(f"DEBUG: Exiting FortiParser.parse() loop at self.i = {self.i}") # DEBUG

        # post‑process policies (still needed for resolving addresses/services)
        print("DEBUG: Starting post-processing.") # DEBUG
        self.model.policies = [self.model.expand_policy(p) for p in self.model.policies]
        print("DEBUG: Finished post-processing.") # DEBUG
        return self.model

    def _skip_block(self):
        depth = 1
        start_line = self.i + 1
        print(f"DEBUG: _skip_block called, starting at line {start_line}. Skipping until depth reaches 0.") # DEBUG
        self.i += 1 # Move past the 'config' line that triggered the skip/handler call
        while self.i < len(self.lines) and depth > 0:
            l = self.lines[self.i].strip()
            if l.startswith('config '):
                depth += 1
                # print(f"DEBUG: _skip_block nested config found at line {self.i+1}. Depth now {depth}.") # DEBUG
            elif self.END_RE.match(l):
                depth -= 1
                # print(f"DEBUG: _skip_block 'end' found at line {self.i+1}. Depth now {depth}.") # DEBUG
            self.i += 1 # Move to the next line
        print(f"DEBUG: _skip_block finished *after* line {self.i}. Final depth: {depth}.") # DEBUG
        # self.i now points to the line *after* the final 'end'

    def _read_block(self):
        """
        Reads a configuration block entry, typically starting with 'edit'
        and containing 'set' commands, ending with 'next'.
        Handles quoted/unquoted names and multi-value set commands correctly.
        Returns a dictionary representing the configuration entry.
        Consumes lines up to and including 'next', or stops *before* 'end'.
        """
        entry = {}
        name = None
        start_i = self.i # Record starting position for debugging

        # The handler moves self.i past 'config ...', so we expect 'edit' or 'end'/'next'
        # Find the 'edit' line for this entry.
        # It should usually be the current line if the section contains 'edit' items.
        if self.i < len(self.lines):
            line = self.lines[self.i].strip()
            m_edit = self.EDIT_RE.match(line)
            if m_edit:
                # Group 1 is quoted content, Group 2 is unquoted (\S+)
                name = m_edit.group(1) or m_edit.group(2)
                entry['name'] = name # Add name to the entry dictionary
                print(f"DEBUG: _read_block found 'edit {name}' at line {self.i + 1}.") # DEBUG
                self.i += 1 # Consume the 'edit' line
            else:
                # If the current line isn't 'edit', it might be 'end' or some other command
                # or a section without 'edit' sub-entries (less common).
                print(f"DEBUG: _read_block did not find 'edit' at start line {self.i + 1}.") # DEBUG

        # Read 'set' commands until 'next' or 'end' (or nested 'config')
        set_found = False # Track if any set commands were found
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()

            # Check for end-of-entry ('next') or end-of-section ('end')
            if self.NEXT_RE.match(line):
                print(f"DEBUG: _read_block found 'next' at line {self.i + 1}.") # DEBUG
                self.i += 1 # Consume 'next'
                break # Finished reading this entry

            if self.END_RE.match(line):
                print(f"DEBUG: _read_block found 'end' at line {self.i + 1} (stopping entry read).") # DEBUG
                # Don't consume 'end', let the calling handler do that
                break # Finished reading the whole section

            # Skip nested config blocks within an entry (should be rare, but handle)
            if line.startswith('config '):
                print(f"Warning: Skipping nested config block inside entry at line {self.i+1}.", file=sys.stderr)
                # Temporarily store current position to resume after skip
                resume_i = self.i
                try:
                    self._skip_block() # self.i is advanced by skip_block
                except Exception as e:
                     print(f"Error skipping nested block: {e}. Resuming after line.", file=sys.stderr)
                     self.i = resume_i + 1 # Fallback: just move past config line
                continue # Continue reading 'set' commands in the outer entry

            # Process 'set' commands
            m_set = self.SET_RE.match(line)
            if m_set:
                set_found = True # Mark that we found at least one 'set'
                key = m_set.group(1).replace('-', '_') # Normalize key (hyphen to underscore)
                value_str = m_set.group(2).strip()
                # print(f"DEBUG: _read_block matched set: key='{key}', value='{value_str[:50]}...'") # DEBUG - potentially too verbose

                # Fields known to potentially contain multiple space-separated, quoted values
                multi_value_quoted_fields = {
                    'member', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service',
                    'allowaccess', # Removed 'interface' here
                    # Add others if identified, e.g., 'networks' in OSPF? 'hosts' in SNMP?
                    'proposal', 'dhcp_server_ip', 'dns_server1', 'dns_server2', # Add more based on config
                    'networks', # OSPF
                    'hosts',    # SNMP community
                }

                if key in multi_value_quoted_fields:
                    # Manual parser for space-separated values, respecting quotes
                    parts = []
                    current_part = ''
                    in_quotes = False
                    escape = False
                    for char in value_str:
                        if escape:
                            current_part += char # Add escaped char directly
                            escape = False
                        elif char == '\\':
                            escape = True # Next char is escaped
                            # Don't add the escape char itself unless needed (e.g., literal \)
                            # current_part += char # Optional: keep escape for later processing
                        elif char == '"':
                            in_quotes = not in_quotes
                            # Don't include the quote characters in the part
                        elif char == ' ' and not in_quotes:
                            if current_part: # Add part if not empty
                                parts.append(current_part)
                                current_part = ''
                        else:
                            current_part += char
                    if current_part: # Add the last part
                        parts.append(current_part)

                    # Clean up escapes (e.g., \\" -> ") if escapes were kept
                    # parts = [p.replace('\\"', '"').replace('\\\\', '\\') for p in parts] # Example cleanup
                    entry[key] = parts # Store the list of parsed values
                else:
                    # For single values, just strip potential *surrounding* quotes
                    entry[key] = value_str.strip('"')

            # Move to the next line
            self.i += 1

        if not set_found and name: # If we had an 'edit' but no 'set' before 'next'/'end'
             print(f"DEBUG: _read_block found 'edit {name}' but no subsequent 'set' commands before line {self.i + 1}.") # DEBUG

        # Return the dictionary for the parsed entry (might be empty if only 'edit'/'next')
        # print(f"DEBUG: _read_block returning entry: {entry}") # DEBUG - Reduced verbosity
        return entry

    def _read_settings(self):
        """
        Reads a block containing only 'set' commands until 'end'.
        Assumes self.i is on the 'config ...' line when called.
        Returns a dictionary of settings. Consumes lines up to *before* 'end'.
        """
        cfg = {}
        print(f"DEBUG: Entering _read_settings at line {self.i + 1}.") # DEBUG
        self.i += 1 # Consume the 'config ...' line that led here
        set_cmds_found = 0 # DEBUG
        while self.i < len(self.lines):
            line = self.lines[self.i].strip()
            if self.END_RE.match(line):
                print(f"DEBUG: _read_settings found 'end' at line {self.i + 1}.") # DEBUG
                # Don't consume 'end', let the calling handler do that
                break # Exit loop, handler expects self.i at 'end' line

            if line.startswith('config '): # Handle unexpected nested config
                print(f"Warning: Unexpected nested config found in settings block at line {self.i+1}. Skipping.", file=sys.stderr)
                resume_i = self.i
                try:
                    self._skip_block()
                except Exception as e:
                    print(f"Error skipping nested block in settings: {e}. Resuming.", file=sys.stderr)
                    self.i = resume_i + 1
                continue

            m_set = self.SET_RE.match(line)
            if m_set:
                key = m_set.group(1).replace('-', '_') # Normalize key
                value_str = m_set.group(2).strip() # Basic value processing
                # Handle potential multi-value fields even in settings blocks if necessary
                # For simplicity, we'll just strip quotes for now. Revisit if needed.
                value = value_str.strip('"')
                cfg[key] = value
                set_cmds_found += 1 # DEBUG
                # print(f"DEBUG: _read_settings found set: {key}={value[:50]}...") # Optional DEBUG
            # else: Skip comments or non-set lines

            self.i += 1 # Move to next line

        print(f"DEBUG: Exiting _read_settings. Found {set_cmds_found} 'set' commands. self.i is {self.i}. Returning: {cfg}") # DEBUG
        # Returns config dict. self.i should be pointing at 'end' or end of file
        return cfg

    # --- Section Handlers ---
    # Ensure handlers correctly call _read_block or _read_settings
    # and consume the final 'end' line using self.i += 1

    def _handle_router_static(self):
        # self.i is on the 'config router static' line
        self.i += 1 # Consume 'config ...' line
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Reads one entry (edit...set...next)
                                     # self.i is now after 'next' or at 'end'
            if blk: # Ensure block is not empty (e.g., just 'edit' then 'next')
                status = blk.get('status', 'enable')
                # Use a default name/ID if 'edit' line was missing or malformed
                # FortiOS static routes use IDs in 'edit', store as 'name' in blk
                route_id = blk.get('name', f"static_route_{len(self.model.routes) + 1}")
                self.model.routes.append({
                    'name':     route_id, # Store the edit ID as name
                    'dst':      blk.get('dst', ''),
                    'gateway':  blk.get('gateway', ''),
                    'device':   blk.get('device', ''),
                    'distance': blk.get('distance', ''),
                    'comment':  blk.get('comment', ''),
                    'status':   status
                })
            # No need to increment self.i here, _read_block handles it
            # The loop condition checks for 'end'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_router_static consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_address(self):
        # self.i is on 'config firewall address'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk: # Check for name from 'edit'
                name = blk['name']
                subnet_val = blk.get('subnet', '')
                start_ip = blk.get('start_ip', '') # Normalized key from _read_block
                end_ip = blk.get('end_ip', '')     # Normalized key from _read_block
                fqdn_val = blk.get('fqdn', '')      # Added FQDN type
                type_val = blk.get('type', 'subnet') # Get type if specified
                country_val = blk.get('country', '') # Geography
                wildcard_val = blk.get('wildcard', '') # Wildcard FQDN

                addr_repr = ''
                # Prioritize specific types
                if type_val == 'fqdn' and fqdn_val:
                     addr_repr = fqdn_val
                elif type_val == 'geography' and country_val:
                     addr_repr = country_val
                elif type_val == 'wildcard' and wildcard_val:
                     addr_repr = wildcard_val
                elif type_val == 'ipmask' and subnet_val:
                     addr_repr = subnet_val
                elif type_val == 'iprange' and start_ip and end_ip:
                     addr_repr = f"{start_ip}-{end_ip}"
                elif type_val == 'iprange' and start_ip: # Range with only start-ip?
                     addr_repr = start_ip
                elif type_val == 'dynamic': # Need 'sub_type' field?
                     addr_repr = f"Dynamic ({blk.get('sub_type', 'N/A')})"
                elif subnet_val: # Default to subnet if present
                     addr_repr = subnet_val
                elif type_val == 'interface-subnet':
                     addr_repr = f"Interface Subnet ({blk.get('interface','N/A')})"


                self.model.addresses[name] = {
                    'type':    type_val,
                    'subnet':  addr_repr, # Use the representative value
                    'comment': blk.get('comment', ''),
                    'associated_interface': blk.get('associated_interface', '') # For some types
                }
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_address consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_addrgrp(self):
        # self.i is on 'config firewall addrgrp'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk:
                # 'member' is now a list parsed by _read_block
                self.model.addr_groups[blk['name']] = blk.get('member', [])
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_addrgrp consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_service_custom(self):
        # self.i is on 'config firewall service custom'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk:
                name = blk['name']
                tcp_range = blk.get('tcp_portrange', '') # Normalized key
                udp_range = blk.get('udp_portrange', '') # Normalized key
                sctp_range = blk.get('sctp_portrange', '')# Normalized key
                icmp_type = blk.get('icmptype', '')
                icmp_code = blk.get('icmpcode', '')
                protocol_num = blk.get('protocol_number', '') # For IP protocol
                protocol = blk.get('protocol', '') # TCP/UDP/SCTP/ICMP/IP

                port_repr = "N/A" # Default
                effective_protocol = protocol # Default

                if protocol == "TCP/UDP/SCTP": # Combined protocol type
                     port_info = []
                     if tcp_range: port_info.append(f"TCP:{tcp_range}")
                     if udp_range: port_info.append(f"UDP:{udp_range}")
                     if sctp_range: port_info.append(f"SCTP:{sctp_range}")
                     port_repr = ' '.join(port_info) if port_info else "N/A"
                     # effective_protocol remains "TCP/UDP/SCTP"
                elif tcp_range:
                     port_repr = tcp_range
                     effective_protocol = "TCP"
                elif udp_range:
                     port_repr = udp_range
                     effective_protocol = "UDP"
                elif sctp_range:
                     port_repr = sctp_range
                     effective_protocol = "SCTP"
                elif protocol == 'ICMP':
                    port_repr = f"Type {icmp_type}" + (f", Code {icmp_code}" if icmp_code else "")
                    effective_protocol = "ICMP"
                elif protocol == 'IP':
                    port_repr = f"Proto {protocol_num}" if protocol_num else "N/A"
                    effective_protocol = "IP"
                # else: Keep default "N/A" port_repr

                self.model.services[name] = {
                    'protocol': effective_protocol, # Use derived protocol
                    'port':     port_repr,
                    'comment':  blk.get('comment', '')
                }
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_service_custom consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_service_group(self):
        # self.i is on 'config firewall service group'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk:
                # 'member' is now a list parsed by _read_block
                self.model.svc_groups[blk['name']] = blk.get('member', [])
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_service_group consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_policy(self):
        # self.i is on 'config firewall policy'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk: # Policy ID is 'name' from 'edit <id>'
                policy_id = blk['name']
                self.model.policies.append({
                    'id':       policy_id,
                    'srcintf':  blk.get('srcintf', []), # Already list
                    'dstintf':  blk.get('dstintf', []), # Already list
                    'srcaddr':  blk.get('srcaddr', []), # Already list
                    'dstaddr':  blk.get('dstaddr', []), # Already list
                    'service':  blk.get('service', []), # Already list
                    'action':   blk.get('action', ''),
                    'status':   blk.get('status', ''),   # enable/disable
                    'schedule': blk.get('schedule', 'always'), # Default to always
                    'comments': blk.get('comments', ''), # Note: FortiOS uses 'comments' plural
                    # NAT specific fields
                    'nat':      blk.get('nat', 'disable'), # Default to disable
                    'ippool':   blk.get('ippool', 'disable'), # Default to disable
                    'poolname': blk.get('poolname', ''), # Name of the ippool if enabled
                    'fixedport': blk.get('fixedport', 'disable'), # NAT fixed port
                    'natip':    blk.get('natip', ''), # Specific NAT IP if not pool
                    # Security Profiles
                    'utm_status': blk.get('utm_status', 'disable'),
                    'profile_protocol_options': blk.get('profile_protocol_options', ''),
                    'av_profile': blk.get('av_profile', ''),
                    'ips_sensor': blk.get('ips_sensor', ''),
                    'webfilter_profile': blk.get('webfilter_profile', ''),
                    'dnsfilter_profile': blk.get('dnsfilter_profile', ''),
                    'application_list': blk.get('application_list', ''),
                    'ssl_ssh_profile': blk.get('ssl_ssh_profile', ''),
                    'dlp_sensor': blk.get('dlp_sensor', ''),
                    'icap_profile': blk.get('icap_profile', ''),
                    # Traffic Shaping
                    'traffic_shaper': blk.get('traffic_shaper', ''),
                    'reverse_traffic_shaper': blk.get('reverse_traffic_shaper', ''),
                    'per_ip_shaper': blk.get('per_ip_shaper', ''),
                    # Logging
                    'logtraffic': blk.get('logtraffic', 'disable'), # utm, all, disable
                    'logtraffic_start': blk.get('logtraffic_start', 'disable')
                })
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_policy consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_system_interface(self):
        # self.i is on 'config system interface'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk:
                name = blk['name']
                ip_field = blk.get('ip', '')
                ip_address = ''
                if ip_field and len(ip_field.split()) > 1: # Check if space exists (IP and Mask)
                    ip_address = f"{ip_field.split()[0]}/{ip_field.split()[1]}" # Combine IP and mask
                elif ip_field: # Assume it's just IP? FortiOS usually includes mask. Check context.
                    ip_address = ip_field

                self.model.interfaces[name] = {
                    'ip':          ip_address, # Use combined IP/mask
                    'type':        blk.get('type', ''),
                    'allowaccess': blk.get('allowaccess', []), # Already list
                    'role':        blk.get('role', ''),
                    'vdom':        blk.get('vdom', 'root'), # Default VDOM?
                    'status':      blk.get('status', 'up'), # Default?
                    'alias':       blk.get('alias', ''),
                    'description': blk.get('description', ''),
                    'mtu_override': blk.get('mtu_override', 'disable'),
                    'mtu':         blk.get('mtu', ''),
                    'speed':       blk.get('speed', 'auto'),
                    'duplex':      blk.get('duplex', 'auto'),
                    'secondary_ip': blk.get('secondary_ip', 'disable'), # Indicates if secondary IPs exist
                    'secondaryip_list': [], # We'll populate this if we parse the nested block
                    'stp':         blk.get('stp', 'disable'),
                    'lldp_profile':blk.get('lldp_profile', 'default')
                }
                # TODO: Potentially parse nested 'secondaryip' block if needed
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_interface consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_system_vlan(self): # Handles 'config system vlan' if it exists (less common than 'switch vlan')
        # self.i is on 'config system vlan'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk: # Name is like 'vlan10' or just the ID? FortiOS uses 'edit <id>'
                vlan_id_from_name = blk.get('name') # Get ID from 'edit <id>'
                if vlan_id_from_name:
                    # Store under the VLAN ID maybe? Or use a generated name if needed
                    vlan_name = f"vlan_{vlan_id_from_name}" # Example naming
                    self.model.vlans[vlan_name] = {
                         'vlanid':    blk.get('vlanid', ''),
                         'interface': blk.get('interface', ''), # Parent physical interface
                         'members':   [] # System VLAN doesn't usually have port members like switch vlan
                     }
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
            print(f"DEBUG: _handle_system_vlan consuming 'end' at line {self.i+1}") # DEBUG
            self.i += 1 # Consume 'end'

    def _handle_switch_controller_managed_switch(self):
        # Placeholder - This section can be complex with nested configs
        print("DEBUG: Entering _handle_switch_controller_managed_switch (basic skip)")
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Read the 'edit <switch_id>' block
             switch_id = blk.get('name')
             if switch_id:
                  print(f"DEBUG: Found managed switch: {switch_id} (Skipping details)")
                  # Need to potentially parse nested 'config ports' etc. here
                  # For now, just consuming the top-level block
             if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                 print(f"DEBUG: Found nested config within switch {switch_id}, skipping.")
                 self._skip_block() # Skip nested blocks like 'config ports'

        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_switch_controller_managed_switch consuming 'end' at line {self.i+1}")
             self.i += 1 # Consume 'end'


    def _handle_switch_controller_vlan(self): # Handles 'config switch-controller vlan'
        # self.i is on 'config switch-controller vlan'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Reads 'edit <vlanid_or_name>' block
            # FortiOS uses 'edit <name>' for switch VLANs, name often 'vlanX'
            vlan_name = blk.get('name')
            if vlan_name:
                 # Extract numeric ID if name follows 'vlanX' pattern
                 vlanid_num = ''.join(filter(str.isdigit, vlan_name))
                 self.model.vlans[vlan_name] = {
                     'vlanid':    vlanid_num if vlanid_num else blk.get('vlanid', ''), # Get explicit vlanid if set
                     'interface': '', # Switch VLANs don't map to a single system interface directly
                     'members':   [] # Port members defined under switch config, not here
                 }
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
            print(f"DEBUG: _handle_switch_controller_vlan consuming 'end' at line {self.i+1}") # DEBUG
            self.i += 1 # Consume 'end'


    def _handle_system_zone(self):
        # self.i is on 'config system zone'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk:
                # 'interface' is now a list parsed by _read_block
                self.model.zones[blk['name']] = {
                    'interface': blk.get('interface', []),
                    'intrazone': blk.get('intrazone', 'deny') # allow/deny
                 }
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_zone consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_vip(self):
        # self.i is on 'config firewall vip'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys already normalized by _read_block
            if blk and 'name' in blk:
                name = blk.pop('name') # Remove name after getting it
                # Add default values or process specific fields if needed
                blk.setdefault('portforward', 'disable')
                blk.setdefault('protocol', '')
                blk.setdefault('extport', '')
                blk.setdefault('mappedport', '')
                blk.setdefault('interface', '') # Interface binding
                self.model.vips[name] = blk # Store remaining normalized key-value pairs
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_vip consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_vipgrp(self):
        # self.i is on 'config firewall vipgrp'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block()
            if blk and 'name' in blk:
                # 'member' is now a list parsed by _read_block
                self.model.vip_groups[blk['name']] = blk.get('member', [])
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_vipgrp consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_ippool(self):
        # self.i is on 'config firewall ippool'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys already normalized
            if blk and 'name' in blk:
                name = blk['name']
                self.model.ippools[name] = {
                    # Access using normalized keys
                    'startip': blk.get('startip', ''), # Check if normalization is needed
                    'endip':   blk.get('endip', ''),
                    'type':    blk.get('type', 'overload'), # Default type?
                    'comment': blk.get('comment', '')
                }
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_ippool consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_system_dhcp_server(self):
        # self.i is on 'config system dhcp server'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys already normalized
            if blk and 'name' in blk: # DHCP server entries use numeric IDs in 'edit <id>'
                 server_id = blk['name'] # 'name' holds the ID
                 entry = {'id': server_id} # Store the ID
                 # Parse ip-range block if present
                 ip_range_raw = blk.get('ip_range', [{}])[0] # Assuming 'ip-range' is a sub-block normalized
                 ip_range_parsed = f"{ip_range_raw.get('start_ip','')} - {ip_range_raw.get('end_ip','')}" if ip_range_raw else ''

                 # Extract relevant top-level fields
                 entry['interface'] = blk.get('interface', '')
                 entry['lease_time'] = blk.get('lease_time', '')
                 entry['default_gateway'] = blk.get('default_gateway', '')
                 entry['netmask'] = blk.get('netmask', '')
                 entry['status'] = blk.get('status', 'enable')
                 entry['ip_range'] = ip_range_parsed # Store parsed range
                 entry['dns_service'] = blk.get('dns_service', 'default')
                 entry['domain'] = blk.get('domain', '')
                 entry['dns_server1'] = blk.get('dns_server1', '')
                 entry['dns_server2'] = blk.get('dns_server2', '')
                 entry['dns_server3'] = blk.get('dns_server3', '')
                 entry['dns_server4'] = blk.get('dns_server4', '')
                 # TODO: Parse nested 'options' block if needed

                 self.model.dhcp_servers.append(entry)
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_dhcp_server consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'


    def _handle_router_ospf(self):
        # self.i is on 'config router ospf'
        settings = self._read_settings() # Reads top-level settings until 'end' or nested 'config'
        # self.i is now at the first nested 'config' or 'end'
        self.model.ospf = settings # Store top-level settings (router-id etc.)

        # Handle nested blocks like 'area', 'network', 'ospf-interface'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            line = self.lines[self.i].strip()
            m = self.SECTION_RE.match(line) # Check for nested config
            if m:
                 nested_sec_raw = m.group(1).lower()
                 nested_sec = nested_sec_raw.replace(' ', '_').replace('-', '_')
                 print(f"DEBUG: OSPF Nested Section Found: {nested_sec_raw}") # DEBUG

                 if nested_sec == 'area':
                     self._handle_router_ospf_area() # Call specific handler
                 elif nested_sec == 'network':
                     self._handle_router_ospf_network()
                 elif nested_sec == 'ospf_interface':
                     self._handle_router_ospf_interface()
                 # Add handlers for other OSPF nested sections as needed
                 else:
                     print(f"Warning: Skipping unhandled OSPF nested section: {nested_sec_raw}", file=sys.stderr)
                     self._skip_block() # Skip unhandled nested section
                 # Handlers should consume their own 'end' and advance self.i
            else:
                 # Should not happen if structure is correct, maybe stray 'set' command?
                 print(f"Warning: Unexpected line in OSPF config: {line[:80]}... Skipping.", file=sys.stderr)
                 self.i += 1 # Skip the unexpected line

        # Consume the final 'end' for 'config router ospf'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_router_ospf consuming final 'end' at line {self.i+1}") # DEBUG
             self.i += 1

    def _handle_router_ospf_area(self):
        # self.i is on 'config area'
        if 'area' not in self.model.ospf: self.model.ospf['area'] = {}
        self.i += 1 # Consume 'config area'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Reads 'edit <area_id>' block
            area_id = blk.get('name') # Area ID from 'edit'
            if area_id:
                self.model.ospf['area'][area_id] = blk # Store area settings
            # Check for nested blocks within area if any (e.g., filter-list)
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                 print(f"Warning: Skipping nested config within OSPF area {area_id}.", file=sys.stderr)
                 self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_router_ospf_area consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end' for 'config area'

    def _handle_router_ospf_network(self):
        # self.i is on 'config network'
        if 'network' not in self.model.ospf: self.model.ospf['network'] = []
        self.i += 1 # Consume 'config network'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Reads 'edit <id>' block
            network_id = blk.get('name') # Network ID from 'edit'
            if network_id:
                 entry = {'id': network_id}
                 entry.update(blk)
                 self.model.ospf['network'].append(entry) # Store network entry
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_router_ospf_network consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end' for 'config network'

    def _handle_router_ospf_interface(self):
        # self.i is on 'config ospf-interface'
        if 'ospf_interface' not in self.model.ospf: self.model.ospf['ospf_interface'] = {}
        self.i += 1 # Consume 'config ospf-interface'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Reads 'edit <name>' block
            name = blk.get('name') # Interface config name from 'edit'
            if name:
                 self.model.ospf['ospf_interface'][name] = blk # Store interface settings
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_router_ospf_interface consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end' for 'config ospf-interface'


    def _handle_router_bgp(self):
        # self.i is on 'config router bgp'
        settings = self._read_settings() # Reads top-level settings until 'end' or nested 'config'
        self.model.bgp = settings # Store top-level settings (AS, router-id etc.)

        # Handle nested blocks like 'neighbor', 'network', 'redistribute'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            line = self.lines[self.i].strip()
            m = self.SECTION_RE.match(line) # Check for nested config
            if m:
                 nested_sec_raw = m.group(1).lower()
                 nested_sec = nested_sec_raw.replace(' ', '_').replace('-', '_')
                 print(f"DEBUG: BGP Nested Section Found: {nested_sec_raw}") # DEBUG

                 if nested_sec == 'neighbor':
                      self._handle_router_bgp_neighbor()
                 elif nested_sec == 'network':
                      self._handle_router_bgp_network()
                 elif nested_sec.startswith('redistribute'): # Handle different redistribute types
                      self._handle_router_bgp_redistribute(nested_sec)
                 # Add handlers for other BGP nested sections (neighbor-group, etc.)
                 else:
                     print(f"Warning: Skipping unhandled BGP nested section: {nested_sec_raw}", file=sys.stderr)
                     self._skip_block()
            else:
                 print(f"Warning: Unexpected line in BGP config: {line[:80]}... Skipping.", file=sys.stderr)
                 self.i += 1

        # Consume the final 'end' for 'config router bgp'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_router_bgp consuming final 'end' at line {self.i+1}") # DEBUG
             self.i += 1


    def _handle_router_bgp_neighbor(self):
         # self.i is on 'config neighbor'
         if 'neighbor' not in self.model.bgp: self.model.bgp['neighbor'] = {}
         self.i += 1 # Consume 'config neighbor'
         while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Reads 'edit <ip_address>' block
             neighbor_ip = blk.get('name') # Neighbor IP from 'edit'
             if neighbor_ip:
                  self.model.bgp['neighbor'][neighbor_ip] = blk # Store neighbor settings
             # Check for nested blocks within neighbor if any
             if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                  print(f"Warning: Skipping nested config within BGP neighbor {neighbor_ip}.", file=sys.stderr)
                  self._skip_block()
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
              print(f"DEBUG: _handle_router_bgp_neighbor consuming 'end' at line {self.i+1}") # DEBUG
              self.i += 1 # Consume 'end' for 'config neighbor'

    def _handle_router_bgp_network(self):
         # self.i is on 'config network' (under BGP)
         if 'network' not in self.model.bgp: self.model.bgp['network'] = []
         self.i += 1 # Consume 'config network'
         while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Reads 'edit <id>' block
             network_id = blk.get('name') # Network ID from 'edit'
             if network_id:
                  entry = {'id': network_id}
                  # BGP network commands often only have 'prefix'
                  entry['prefix'] = blk.get('prefix', '')
                  self.model.bgp['network'].append(entry) # Store network entry
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
              print(f"DEBUG: _handle_router_bgp_network consuming 'end' at line {self.i+1}") # DEBUG
              self.i += 1 # Consume 'end' for 'config network'

    def _handle_router_bgp_redistribute(self, section_name):
        # self.i is on 'config redistribute <type>'
        if 'redistribute' not in self.model.bgp: self.model.bgp['redistribute'] = {}
        redist_type = section_name.replace('redistribute_', '') # Extract type (connected, static, ospf, etc.)
        print(f"DEBUG: Handling BGP redistribute type: {redist_type}") # DEBUG
        # This is usually a settings block per type
        settings = self._read_settings()
        self.model.bgp['redistribute'][redist_type] = settings
        # Consume the 'end' for this redistribute type
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
            print(f"DEBUG: _handle_router_bgp_redistribute ({redist_type}) consuming 'end' at line {self.i+1}") # DEBUG
            self.i += 1

    def _handle_vpn_ipsec_phase1_interface(self):
        # self.i is on 'config vpn ipsec phase1-interface'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk:
                name = blk.pop('name') # Get name, remove from dict
                # Process proposals if needed (might be list)
                if 'proposal' in blk and isinstance(blk['proposal'], str):
                    blk['proposal'] = blk['proposal'].split() # Convert space separated string to list
                blk.setdefault('dhgrp', '') # Diffie-Hellman Group
                blk.setdefault('keylife', '') # Phase 1 lifetime
                blk.setdefault('dpd', 'disable') # Dead Peer Detection
                blk.setdefault('dpd_retryinterval', '')
                blk.setdefault('dpd_retrycount', '')
                blk.setdefault('authmethod', 'psk') # psk/signature
                blk.setdefault('psksecret', '***') # Placeholder, don't store real key
                blk.setdefault('interface', '')
                blk.setdefault('remote_gw', '')
                self.model.phase1[name] = blk # Store rest of normalized dict
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_vpn_ipsec_phase1_interface consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_vpn_ipsec_phase2_interface(self):
        # self.i is on 'config vpn ipsec phase2-interface'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk:
                name = blk.pop('name')
                # Process proposals if needed (might be list)
                if 'proposal' in blk and isinstance(blk['proposal'], str):
                    blk['proposal'] = blk['proposal'].split()
                # Process selectors
                # Simplified - assuming direct fields like src-addr-type, dst-addr-type, src-name, dst-name etc. exist
                # Needs verification against actual config structure
                blk.setdefault('src_addr_type', blk.get('src_addr_type')) # Example: ensure keys exist
                blk.setdefault('dst_addr_type', blk.get('dst_addr_type'))
                blk.setdefault('src_name', blk.get('src_name', [])) # Default to empty list if list expected
                blk.setdefault('dst_name', blk.get('dst_name', []))
                blk.setdefault('src_subnet', blk.get('src_subnet'))
                blk.setdefault('dst_subnet', blk.get('dst_subnet'))
                blk.setdefault('phase1name', '')
                blk.setdefault('pfs', 'disable') # Perfect Forward Secrecy
                blk.setdefault('dhgrp', '')      # DH Group for PFS
                blk.setdefault('keylifeseconds', '') # Phase 2 lifetime
                self.model.phase2[name] = blk
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_vpn_ipsec_phase2_interface consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_shaper_traffic_shaper(self):
        # self.i is on 'config firewall shaper traffic-shaper'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk:
                name = blk.pop('name')
                self.model.traffic_shapers[name] = blk
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_shaper_traffic_shaper consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_shaper_per_ip_shaper(self):
        # self.i is on 'config firewall shaper per-ip-shaper'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk:
                name = blk.pop('name')
                self.model.shaper_per_ip[name] = blk # Check model key name
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_shaper_per_ip_shaper consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_firewall_dos_policy(self):
        # self.i is on 'config firewall DoS-policy'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk: # Uses numeric ID in 'edit <id>'
                policy_id = blk['name']
                entry = {'id': policy_id}
                # Need to handle nested 'anomaly' block if present
                # For now, just store top-level fields
                entry.update({k: v for k, v in blk.items() if k != 'name'}) # Add other normalized key-value pairs
                self.model.dos_policies.append(entry)
            # _read_block advances self.i
            # Skip nested anomaly block for now
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config anomaly'):
                 print("DEBUG: Skipping nested 'config anomaly' in DoS policy.")
                 self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_firewall_dos_policy consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_system_snmp_sysinfo(self):
        # self.i is on 'config system snmp sysinfo'
        self.model.snmp_sysinfo = self._read_settings() # Keys normalized
        # Consume the 'end'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_snmp_sysinfo consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1

    def _handle_system_snmp_community(self):
        # self.i is on 'config system snmp community'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk: # Uses numeric ID in 'edit <id>'
                 community_id = blk['name']
                 entry = {'id': community_id} # Store the ID
                 # Handle nested 'hosts' block if present
                 hosts_list = []
                 if 'hosts' in blk: # Check if 'hosts' key exists from _read_block (may need refinement)
                      # Assuming _read_block returns 'hosts' as a list of dicts or similar
                      # Placeholder: Just store the raw value for now
                      hosts_list = blk.get('hosts')
                      print(f"DEBUG: Found SNMP hosts block (raw): {hosts_list}") #DEBUG
                 entry.update({k: v for k, v in blk.items() if k != 'name'}) # Add other normalized key-value pairs
                 entry['hosts_parsed'] = hosts_list # Store parsed hosts if available
                 self.model.snmp_communities[community_id] = entry # Store by ID
            # _read_block advances self.i
            # Handle nested hosts block if necessary (requires dedicated parser)
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config hosts'):
                print("DEBUG: Skipping nested 'config hosts' in SNMP community.")
                self._skip_block()

        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_snmp_community consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_user_ldap(self):
        # self.i is on 'config user ldap'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk:
                name = blk.pop('name')
                self.model.ldap_servers[name] = blk
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_user_ldap consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_system_admin(self):
        # self.i is on 'config system admin'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk:
                name = blk.pop('name')
                # Need to handle password/peer-auth fields carefully (sensitive)
                blk.pop('password', None) # Remove password field if parsed
                blk.pop('peer_auth', None)
                blk.pop('ssh_public_key1', None) # Remove SSH keys
                blk.pop('ssh_public_key2', None)
                blk.pop('ssh_public_key3', None)
                self.model.admins[name] = blk
            # _read_block advances self.i
            # Handle nested blocks like vdom, accprofile-override if needed
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                 print(f"Warning: Skipping nested config within admin {blk.get('name')}.", file=sys.stderr)
                 self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_admin consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_system_ha(self):
        # self.i is on 'config system ha'
        self.model.ha = self._read_settings() # Keys normalized
        # Add defaults for commonly checked fields
        self.model.ha.setdefault('group_name', '')
        self.model.ha.setdefault('mode', 'a-p')
        self.model.ha.setdefault('priority', '')
        self.model.ha.setdefault('monitor', '')
        self.model.ha.setdefault('override', 'disable')
        self.model.ha.setdefault('hbdev', '')
        # Consume the 'end'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_ha consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1

    def _handle_system_ntp(self):
        # self.i is on 'config system ntp'
        self.model.ntp = self._read_settings() # Keys normalized
        # Consume the 'end'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_ntp consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1

    def _handle_system_dns(self):
        # self.i is on 'config system dns'
        self.model.dns = self._read_settings() # Keys normalized
        # Consume the 'end'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_system_dns consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1

    def _handle_vpn_ssl_settings(self):
        # self.i is on 'config vpn ssl settings'
        self.model.ssl_settings = self._read_settings() # Keys normalized
        # Consume the 'end'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_vpn_ssl_settings consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1

    def _handle_vpn_ssl_web_portal(self):
        # self.i is on 'config vpn ssl web portal'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk:
                name = blk.pop('name')
                # Handle nested blocks like 'bookmark-group' if needed
                self.model.ssl_portals[name] = blk
            # _read_block advances self.i
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                 print(f"Warning: Skipping nested config within SSL portal {blk.get('name')}.", file=sys.stderr)
                 self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_vpn_ssl_web_portal consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_vpn_ssl_web_policy(self): # SSL VPN Policies often use IDs
        # self.i is on 'config vpn ssl web policy'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk: # Uses numeric ID ('name')
                policy_id = blk['name']
                entry = {'id': policy_id}
                entry.update({k: v for k, v in blk.items() if k != 'name'}) # Add other fields
                self.model.ssl_policies.append(entry)
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_vpn_ssl_web_policy consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'

    def _handle_router_vrrp(self): # Handles 'config router vrrp' - list block
        # self.i is on 'config router vrrp'
        self.i += 1 # Consume 'config ...'
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
            blk = self._read_block() # Keys normalized
            if blk and 'name' in blk: # Uses ID like 'edit <intf_index>:<vrf_id>' e.g., 'edit 1:1'
                 vrrp_id_str = blk['name'] # The composite ID string
                 try:
                     # Attempt to parse ID into interface index and VRID
                     intf_index, vrid = map(int, vrrp_id_str.split(':'))
                     vrrp_id_key = f"{intf_index}:{vrid}" # Use parsed key
                 except ValueError:
                     print(f"Warning: Could not parse VRRP ID '{vrrp_id_str}'. Using raw string as key.", file=sys.stderr)
                     vrrp_id_key = vrrp_id_str # Fallback to raw string

                 entry = {'id': vrrp_id_key}
                 entry.update({k: v for k, v in blk.items() if k != 'name'})
                 self.model.vrrp[vrrp_id_key] = entry # Store by composite ID key
            # _read_block advances self.i
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
             print(f"DEBUG: _handle_router_vrrp consuming 'end' at line {self.i+1}") # DEBUG
             self.i += 1 # Consume 'end'


    # --- Add handlers for all sections defined in ConfigModel ---
    # Using _read_settings() for settings blocks
    # Using _read_block() and loop for list blocks (those with 'edit')
    # MAKE SURE to consume the final 'end' in each handler.

    def _handle_system_global(self):
        self.model.system_global = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_antivirus_profile(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.antivirus[name] = blk
            # Skip nested blocks if any
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in antivirus profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_ips_sensor(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.ips[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in ips sensor {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_webfilter_profile(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.web_filter[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in webfilter profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_application_list(self): # Maps to app_control
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.app_control[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in application list {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_dlp_sensor(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.dlp[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in dlp sensor {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_emailfilter_profile(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.email_filter[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in emailfilter profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_voip_profile(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.voip[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in voip profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_waf_profile(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.waf[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in waf profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_ssh_filter_profile(self): # Maps to ssl_inspection in model? Need check
         print("Warning: Mapping ssh_filter_profile handler needed (using ssl_inspection).", file=sys.stderr)
         self.i += 1
         while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
             blk = self._read_block(); name = blk.pop('name', None)
             if name: self.model.ssl_inspection[name] = blk # Assuming maps here
             if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                 print(f"Warning: Skipping nested config in ssh_filter_profile {name}.", file=sys.stderr)
                 self._skip_block()
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_ssl_ssh_profile(self): # Handles SSL/SSH Inspection
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.ssl_inspection[name] = blk # Check model key
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in ssl_ssh_profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_icap_profile(self): # Handles ICAP profiles (not servers)
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.icap[name] = blk # Check model key (used for profiles)
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in icap profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_gtp_profile(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.gtp[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in gtp profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_user_radius(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name:
                blk.pop('secret', None) # Remove secret
                self.model.radius_servers[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in radius server {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_user_group(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.user_groups[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in user group {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_firewall_schedule_group(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.schedule_groups[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in schedule group {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_firewall_schedule_onetime(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.schedule_onetime[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_firewall_schedule_recurring(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.schedule_recurring[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_firewall_sniffer(self): # config firewall sniffer (uses ID)
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block()
            sniffer_id = blk.get('name') # 'edit <id>'
            if sniffer_id:
                 entry = {'id': sniffer_id}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                 # Assuming model stores sniffer profiles in sniffer_profile dict by ID
                 self.model.sniffer_profile[sniffer_id] = entry
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                 print(f"Warning: Skipping nested config in sniffer profile {sniffer_id}.", file=sys.stderr)
                 self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1


    def _handle_wanopt_profile(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.wan_opt[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in wanopt profile {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_user_fortitoken(self): # Uses 'edit <serial_number>'
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block()
            serial = blk.get('name')
            if serial:
                 entry = {'serial': serial}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                 self.model.fortitoken[serial] = entry
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_fortiguard(self):
        self.model.fortiguard = self._read_settings() # Top level settings
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_log_syslogd_setting(self): # Example specific log setting handler
        print("DEBUG: Handling 'log syslogd setting'")
        # Need to store this appropriately, e.g., self.model.log_settings['syslogd'] = ...
        settings = self._read_settings()
        if 'log_settings' not in self.model.__dict__: self.model.log_settings = {}
        self.model.log_settings['syslogd'] = settings
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1


    def _handle_system_sdwan(self): # Top level SDWAN settings
        self.model.sd_wan = self._read_settings()
        # Handle nested members, service, health-check etc.
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             line = self.lines[self.i].strip()
             m = self.SECTION_RE.match(line)
             if m:
                 nested_sec_raw = m.group(1).lower()
                 nested_sec = nested_sec_raw.replace(' ', '_').replace('-', '_')
                 print(f"DEBUG: SDWAN Nested Section Found: {nested_sec_raw}") # DEBUG
                 if nested_sec == 'members':
                     self._handle_system_sdwan_members()
                 elif nested_sec == 'service':
                      self._handle_system_sdwan_service()
                 elif nested_sec == 'health_check':
                      self._handle_system_sdwan_health_check()
                 else:
                     print(f"Warning: Skipping unhandled SDWAN nested section: {nested_sec_raw}", file=sys.stderr)
                     self._skip_block()
             else:
                 print(f"Warning: Unexpected line in SDWAN config: {line[:80]}... Skipping.", file=sys.stderr)
                 self.i += 1
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_sdwan_members(self):
         # self.i is on 'config members'
         if 'members' not in self.model.sd_wan: self.model.sd_wan['members'] = []
         self.i += 1 # Consume 'config members'
         while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Reads 'edit <id>' block
             member_id = blk.get('name') # Member ID from 'edit'
             if member_id:
                  entry = {'id': member_id}
                  entry.update({k:v for k,v in blk.items() if k != 'name'})
                  self.model.sd_wan['members'].append(entry) # Store member entry
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
              print(f"DEBUG: _handle_system_sdwan_members consuming 'end' at line {self.i+1}") # DEBUG
              self.i += 1 # Consume 'end' for 'config members'

    def _handle_system_sdwan_service(self):
         # self.i is on 'config service'
         if 'service' not in self.model.sd_wan: self.model.sd_wan['service'] = []
         self.i += 1 # Consume 'config service'
         while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Reads 'edit <id>' block
             service_id = blk.get('name') # Service ID from 'edit'
             if service_id:
                  entry = {'id': service_id}
                  entry.update({k:v for k,v in blk.items() if k != 'name'})
                  self.model.sd_wan['service'].append(entry) # Store service entry
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
              print(f"DEBUG: _handle_system_sdwan_service consuming 'end' at line {self.i+1}") # DEBUG
              self.i += 1 # Consume 'end' for 'config service'

    def _handle_system_sdwan_health_check(self):
         # self.i is on 'config health-check'
         if 'health_check' not in self.model.sd_wan: self.model.sd_wan['health_check'] = {}
         self.i += 1 # Consume 'config health-check'
         while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Reads 'edit <name>' block
             hc_name = blk.get('name') # Health Check name from 'edit'
             if hc_name:
                  self.model.sd_wan['health_check'][hc_name] = {k:v for k,v in blk.items() if k != 'name'}
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
              print(f"DEBUG: _handle_system_sdwan_health_check consuming 'end' at line {self.i+1}") # DEBUG
              self.i += 1 # Consume 'end' for 'config health-check'

    def _handle_firewall_ldb_monitor(self): # load balance monitor
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name:
                 if 'load_balance' not in self.model.__dict__: self.model.load_balance = {}
                 if 'monitors' not in self.model.load_balance: self.model.load_balance['monitors'] = {}
                 self.model.load_balance['monitors'][name] = blk # Store monitor by name
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    # Add handlers for other load-balance sections (virtual-server, real-server, etc.)

    def _handle_wireless_controller_setting(self):
        self.model.wireless_controller = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_switch_controller_global(self):
        self.model.switch_controller = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_fortisandbox(self):
        self.model.sandbox = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    # Certificates need specific handling based on type (local, ca, etc.)
    def _handle_vpn_certificate_local(self):
         self.i += 1
         while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
             blk = self._read_block(); name = blk.pop('name', None)
             if name:
                  if 'certificate' not in self.model.__dict__: self.model.certificate = {}
                  blk['type'] = 'local' # Add type info
                  blk.pop('private_key', None) # Remove sensitive key
                  blk.pop('certificate', None) # Remove cert content
                  self.model.certificate[name] = blk
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_vpn_certificate_ca(self):
          self.i += 1
          while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
              blk = self._read_block(); name = blk.pop('name', None)
              if name:
                   if 'certificate' not in self.model.__dict__: self.model.certificate = {}
                   blk['type'] = 'ca' # Add type info
                   blk.pop('certificate', None) # Remove cert content
                   self.model.certificate[name] = blk
          if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_vpn_certificate_remote(self):
          self.i += 1
          while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
              blk = self._read_block(); name = blk.pop('name', None)
              if name:
                   if 'certificate' not in self.model.__dict__: self.model.certificate = {}
                   blk['type'] = 'remote' # Add type info
                   blk.pop('certificate', None) # Remove cert content
                   self.model.certificate[name] = blk
          if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_vpn_certificate_crl(self):
          self.i += 1
          while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
              blk = self._read_block(); name = blk.pop('name', None)
              if name:
                   if 'certificate' not in self.model.__dict__: self.model.certificate = {}
                   blk['type'] = 'crl' # Add type info
                   blk.pop('crl', None) # Remove crl content
                   self.model.certificate[name] = blk
          if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1


    def _handle_user_saml(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.saml[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_user_fsso(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name:
                blk.pop('password', None) # Remove password
                self.model.fsso[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_automation_action(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name:
                 if 'automation' not in self.model.__dict__: self.model.automation = {}
                 if 'action' not in self.model.automation: self.model.automation['action'] = {}
                 self.model.automation['action'][name] = blk # Store action by name
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    # Need handlers for automation-trigger, automation-stitch as well

    def _handle_system_sdn_connector(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.sdn_connector[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                print(f"Warning: Skipping nested config in sdn connector {name}.", file=sys.stderr)
                self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_extender_controller_extender(self): # Note long name
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); extender_id = blk.get('name') # Uses ID
            if extender_id:
                 entry = {'id': extender_id}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                 self.model.extender[extender_id] = entry
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_vpn_l2tp(self):
        self.model.vpn_l2tp = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_vpn_pptp(self):
        self.model.vpn_pptp = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_vpn_ssl_client(self):
         # This section seems unlikely based on FortiOS structure.
         # 'vpn ssl settings' usually covers client-related global settings.
         # Verify if 'config vpn ssl client' actually exists.
         print("Warning: Handling 'vpn ssl client' as settings. Verify structure.", file=sys.stderr)
         self.model.vpn_ssl_client = self._read_settings() # Client settings? Or list? Verify
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_replacemsg_group(self): # Need to handle sub-groups
        print("Warning: Handler for system_replacemsg_group is basic.", file=sys.stderr)
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
             blk = self._read_block(); name = blk.pop('name', None)
             if name:
                  if 'system_replacemsg' not in self.model.__dict__: self.model.system_replacemsg = {}
                  self.model.system_replacemsg[name] = blk # Store by group name
             if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                  print(f"Warning: Skipping nested config in replacemsg group {name}.", file=sys.stderr)
                  self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1


    def _handle_system_accprofile(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.system_accprofile[name] = blk
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                 print(f"Warning: Skipping nested config in accprofile {name}.", file=sys.stderr)
                 self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_api_user(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.get('name') # Uses username/ID
            if name:
                 entry = {'id': name}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                 entry.pop('api_key', None) # Remove API key
                 self.model.system_api_user[name] = entry
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                  print(f"Warning: Skipping nested config in api user {name}.", file=sys.stderr)
                  self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_sso_admin(self):
        self.model.system_sso_admin = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_password_policy(self):
        self.model.system_password_policy = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_firewall_interface_policy(self): # Maps to system_interface_policy?
         print("DEBUG: Handling 'firewall interface-policy'")
         self.i += 1
         while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
              blk = self._read_block(); policy_id = blk.get('name') # Uses ID
              if policy_id:
                   entry = {'id': policy_id}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                   if 'system_interface_policy' not in self.model.__dict__: self.model.system_interface_policy = {}
                   self.model.system_interface_policy[policy_id] = entry
              if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                  print(f"Warning: Skipping nested config in interface policy {policy_id}.", file=sys.stderr)
                  self._skip_block()
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1


    def _handle_system_csf(self): # Security Fabric settings
        self.model.system_csf = self._read_settings()
        # Handle nested 'trusted-list' etc. if needed
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             line = self.lines[self.i].strip()
             m = self.SECTION_RE.match(line)
             if m:
                 nested_sec_raw = m.group(1).lower()
                 print(f"DEBUG: CSF Nested Section Found: {nested_sec_raw}") # DEBUG
                 print(f"Warning: Skipping unhandled CSF nested section: {nested_sec_raw}", file=sys.stderr)
                 self._skip_block()
             else:
                 print(f"Warning: Unexpected line in CSF config: {line[:80]}... Skipping.", file=sys.stderr)
                 self.i += 1
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_central_management(self):
        self.model.system_central_mgmt = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_auto_update(self):
        self.model.system_auto_update = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_session_ttl(self):
        self.model.system_session_ttl = self._read_settings()
        # Handle nested 'port' block
        while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             line = self.lines[self.i].strip()
             m = self.SECTION_RE.match(line)
             if m:
                 nested_sec_raw = m.group(1).lower()
                 if nested_sec_raw == 'port':
                     self._handle_system_session_ttl_port()
                 else:
                     print(f"Warning: Skipping unhandled session-ttl nested section: {nested_sec_raw}", file=sys.stderr)
                     self._skip_block()
             else:
                 print(f"Warning: Unexpected line in session-ttl config: {line[:80]}... Skipping.", file=sys.stderr)
                 self.i += 1
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_session_ttl_port(self):
         # self.i is on 'config port'
         if 'port' not in self.model.system_session_ttl: self.model.system_session_ttl['port'] = []
         self.i += 1 # Consume 'config port'
         while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Reads 'edit <id>' block
             port_id = blk.get('name') # Port ID from 'edit'
             if port_id:
                  entry = {'id': port_id}
                  entry.update({k:v for k,v in blk.items() if k != 'name'})
                  self.model.system_session_ttl['port'].append(entry) # Store port entry
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
              print(f"DEBUG: _handle_system_session_ttl_port consuming 'end' at line {self.i+1}") # DEBUG
              self.i += 1 # Consume 'end' for 'config port'


    def _handle_system_gre_tunnel(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.system_gre_tunnel[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_ddns(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); ddns_id = blk.get('name') # Uses ID
            if ddns_id:
                 entry = {'id': ddns_id}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                 self.model.system_ddns[ddns_id] = entry
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_dns_database(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None) # Zone name
            if name:
                 if 'system_dns_database' not in self.model.__dict__: self.model.system_dns_database = {}
                 self.model.system_dns_database[name] = blk # Store zone settings
                 # Handle nested dns-entry
                 while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
                      line = self.lines[self.i].strip()
                      m = self.SECTION_RE.match(line)
                      if m and m.group(1).lower() == 'dns-entry':
                           self._handle_system_dns_database_dns_entry(name) # Pass zone name
                      else:
                          # Reached 'next' for the zone or 'end' for the db
                          break
            # _read_block for zone consumes 'next', loop continues or exits

        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1 # Consume final 'end' for dns-database

    def _handle_system_dns_database_dns_entry(self, zone_name):
         # self.i is on 'config dns-entry'
         zone_data = self.model.system_dns_database.get(zone_name, {})
         if 'dns_entry' not in zone_data: zone_data['dns_entry'] = []
         self.i += 1 # Consume 'config dns-entry'
         while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Reads 'edit <id>' block
             entry_id = blk.get('name') # Entry ID from 'edit'
             if entry_id:
                  entry = {'id': entry_id}
                  entry.update({k:v for k,v in blk.items() if k != 'name'})
                  zone_data['dns_entry'].append(entry) # Store entry in its zone
         self.model.system_dns_database[zone_name] = zone_data # Update zone data
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
              print(f"DEBUG: _handle_system_dns_database_dns_entry consuming 'end' at line {self.i+1}") # DEBUG
              self.i += 1 # Consume 'end' for 'config dns-entry'


    def _handle_system_dns_server(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None) # Interface name?
            if name: self.model.system_dns_server[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_proxy_arp(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
             blk = self._read_block(); parp_id = blk.get('name') # Uses ID
             if parp_id:
                  entry = {'id': parp_id}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                  self.model.system_proxy_arp[parp_id] = entry
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_virtual_wire_pair(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.system_virtual_wire_pair[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_wccp(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
             blk = self._read_block(); service_id = blk.get('name') # Uses ID (e.g., '0', '1')
             if service_id:
                  entry = {'id': service_id}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                  if 'system_wccp' not in self.model.__dict__: self.model.system_wccp = {}
                  self.model.system_wccp[service_id] = entry
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1


    def _handle_system_sit_tunnel(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.system_sit_tunnel[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_ipip_tunnel(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.system_ipip_tunnel[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_vxlan(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.system_vxlan[name] = blk
            # Handle nested remote_ip block
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config remote-ip'):
                 self._handle_system_vxlan_remote_ip(name)
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_vxlan_remote_ip(self, vxlan_name):
         # self.i is on 'config remote-ip'
         vxlan_data = self.model.system_vxlan.get(vxlan_name, {})
         if 'remote_ip' not in vxlan_data: vxlan_data['remote_ip'] = []
         self.i += 1 # Consume 'config remote-ip'
         while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
             blk = self._read_block() # Reads 'edit <ip_address>' block
             remote_ip = blk.get('name') # IP from 'edit'
             if remote_ip:
                  entry = {'ip': remote_ip} # Just store the IP
                  vxlan_data['remote_ip'].append(entry) # Store entry in its vxlan config
         self.model.system_vxlan[vxlan_name] = vxlan_data # Update vxlan data
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
              print(f"DEBUG: _handle_system_vxlan_remote_ip consuming 'end' at line {self.i+1}") # DEBUG
              self.i += 1 # Consume 'end' for 'config remote-ip'

    def _handle_system_geneve(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name: self.model.system_geneve[name] = blk
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_network_visibility(self):
        self.model.system_network_visibility = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_ptp(self):
        self.model.system_ptp = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_tos_based_priority(self):
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
             blk = self._read_block(); priority_id = blk.get('name') # Uses ID
             if priority_id:
                  entry = {'id': priority_id}; entry.update({k:v for k,v in blk.items() if k != 'name'})
                  self.model.system_tos_based_priority[priority_id] = entry
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_email_server(self):
        self.model.system_email_server = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_dnsfilter_profile(self): # Note name change vs model key
        self.i += 1
        while not (self.i >= len(self.lines) or self.END_RE.match(self.lines[self.i].strip())):
            blk = self._read_block(); name = blk.pop('name', None)
            if name:
                if 'system_dns_filter' not in self.model.__dict__: self.model.system_dns_filter = {}
                self.model.system_dns_filter[name] = blk # Maps to system_dns_filter
            if self.i < len(self.lines) and self.lines[self.i].strip().startswith('config '):
                 print(f"Warning: Skipping nested config in dnsfilter profile {name}.", file=sys.stderr)
                 self._skip_block()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_ips_urlfilter_dns(self): # Needs model field?
         print("Warning: Model field for ips_urlfilter_dns needed.", file=sys.stderr)
         self.model.system_ips_urlfilter_dns = self._read_settings() # Store as settings for now
         if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1


    def _handle_system_fm(self): # FortiManager settings
        self.model.system_fm = self._read_settings()
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_system_fortianalyzer(self): # Alias for log fortianalyzer setting
        print("DEBUG: Handling 'system fortianalyzer' (alias for log setting)")
        settings = self._read_settings()
        if 'system_fortianalyzer' not in self.model.__dict__: self.model.system_fortianalyzer = {}
        self.model.system_fortianalyzer.update(settings) # Merge into main faz settings
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_log_fortianalyzer_setting(self): # Original name
        print("DEBUG: Handling 'log fortianalyzer setting'")
        settings = self._read_settings()
        if 'system_fortianalyzer' not in self.model.__dict__: self.model.system_fortianalyzer = {}
        self.model.system_fortianalyzer.update(settings) # Merge into main faz settings
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1

    def _handle_log_fortisandbox_setting(self): # Original name
        print("DEBUG: Handling 'log fortisandbox setting'")
        settings = self._read_settings()
        # Merge into main sandbox settings?
        if 'system_fortisandbox' not in self.model.__dict__: self.model.system_fortisandbox = {}
        self.model.system_fortisandbox.update(settings)
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()): self.i += 1


    # Generic section handler for unknown config sections
    def _handle_generic_section(self, raw_section_name, normalized_section_name):
        """
        Generic handler for unrecognized configuration sections.
        Stores entries in a dictionary under model.unhandled_sections.
        
        Args:
            raw_section_name: The original section name from the config
            normalized_section_name: The section name with spaces/hyphens replaced by underscores
        """
        print(f"DEBUG: Generic handler for section '{raw_section_name}'")
        
        # Initialize unhandled_sections dict if not exists
        if not hasattr(self.model, 'unhandled_sections'):
            self.model.unhandled_sections = {}
            
        # Create section container if not exists
        if normalized_section_name not in self.model.unhandled_sections:
            self.model.unhandled_sections[normalized_section_name] = {}
            
        # Determine where to store this section's data
        target_dict = self.model.unhandled_sections[normalized_section_name]
        
        # Handle VDOM context if present
        if self.current_vdom:
            if 'vdom_specific' not in target_dict:
                target_dict['vdom_specific'] = {}
            if self.current_vdom not in target_dict['vdom_specific']:
                target_dict['vdom_specific'][self.current_vdom] = []
            entries_list = target_dict['vdom_specific'][self.current_vdom]
        else:
            if 'entries' not in target_dict:
                target_dict['entries'] = []
            entries_list = target_dict['entries']
        
        self.i += 1  # Consume 'config ...' line
        
        # Try to determine the type of section (edit-blocks vs settings-only)
        try:
            # Look ahead to see if we have 'edit' commands
            has_edit_blocks = False
            peek_i = self.i
            while peek_i < len(self.lines) and not self.END_RE.match(self.lines[peek_i].strip()):
                if self.EDIT_RE.match(self.lines[peek_i].strip()):
                    has_edit_blocks = True
                    break
                peek_i += 1
                
            if has_edit_blocks:
                # Process edit blocks for this section
                while self.i < len(self.lines) and not self.END_RE.match(self.lines[self.i].strip()):
                    blk = self._read_block()
                    if blk:
                        entries_list.append(blk)
            else:
                # Process as settings-only section
                settings = self._read_settings()
                entries_list.append(settings)
                
        except Exception as e:
            print(f"Error in generic handler for '{raw_section_name}': {e}. Skipping section.", file=sys.stderr)
            self._skip_block()
            
        # Consume the final 'end'
        if self.i < len(self.lines) and self.END_RE.match(self.lines[self.i].strip()):
            self.i += 1

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
    p = argparse.ArgumentParser(description="FortiGate Comprehensive Table Parser & Diagram Generator")
    p.add_argument('config_file', help="FortiGate CLI export text file")
    p.add_argument('--output', default='network_topology', help="Base name for output files (diagrams, reports)")
    # Path Tracing Arguments
    p.add_argument('--trace-src', help="Source IP address for path trace")
    p.add_argument('--trace-dst', help="Destination IP address for path trace")
    p.add_argument('--trace-port', help="Destination port for path trace (required if src/dst provided)")
    p.add_argument('--trace-proto', default='tcp', help="Protocol for path trace (tcp, udp, icmp - default: tcp)")

    args = p.parse_args()

    try:
        text = open(args.config_file, encoding='utf-8').read()
    except OSError as e:
        sys.stderr.write(f"Error opening {args.config_file}: {e}\\n")
        sys.exit(1)

    model = FortiParser(text.splitlines()).parse()
    generator = NetworkDiagramGenerator(model) # Initialize generator regardless

    # --- Conditional Execution: Trace or Tables/Diagram ---
    if args.trace_src and args.trace_dst:
        if not args.trace_port:
             print("Error: --trace-port is required when using --trace-src and --trace-dst.", file=sys.stderr)
             sys.exit(1)

        print(f"\\n--- Performing Network Path Trace ---")
        print(f"Source:      {args.trace_src}")
        print(f"Destination: {args.trace_dst}")
        print(f"Port:        {args.trace_port}")
        print(f"Protocol:    {args.trace_proto}")
        print("-" * 35)

        # Run the trace
        path_result, status_msg = generator.trace_network_path(
            source_ip=args.trace_src,
            dest_ip=args.trace_dst,
            dest_port=args.trace_port,
            protocol=args.trace_proto
        )

        # Print the results
        print(f"\\n--- Trace Result ---")
        print(f"Status: {status_msg}")
        if path_result:
            print("\\nPath Details:")
            # Simple print for now, could be formatted better
            for hop_info in path_result:
                 print(f"  Hop {hop_info.get('hop')}: {hop_info.get('type')}")
                 for key, value in hop_info.items():
                     if key not in ['hop', 'type']:
                         print(f"    {key}: {value}")
        print("-" * 20)

    else:
        # --- Default Behavior: Generate Connectivity Tree --- 
        print("No trace arguments provided. Generating connectivity tree summary...")
        connectivity_tree = generator.generate_connectivity_tree()
        print(connectivity_tree)
 # --- Restoring Table/Diagram Generation ---
        # Static Routes (with Type & Enabled)
        rows = []
        for r in model.routes:
            # determine if destination is CIDR or interface service
            if re.match(r'^\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+$', r['dst']):
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
        rows = [[n, a['type'], a['subnet'], a.get('associated_interface',''), a['comment']]
                for n,a in model.addresses.items()]
        print_table("Address Objects", ["Name","Type","Address/Subnet/FQDN","Assoc. Interface","Comment"], rows)

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
        rows = [[n, i.get('ip',''), i.get('type',''), ','.join(i.get('allowaccess',[])),
                 i.get('role',''), i.get('vdom',''), i.get('alias',''), i.get('description',''),
                 f"{i.get('mtu','N/A')}{' (ovr)' if i.get('mtu_override')=='enable' else ''}",
                 i.get('status',''), i.get('speed',''), i.get('duplex','')]
                for n,i in model.interfaces.items()]
        print_table("Interfaces", ["Name","IP/Mask","Type","Access","Role","VDOM","Alias","Description","MTU","Status","Speed","Duplex"], rows)

        # VLANs
        rows = [[n, v['vlanid'], v['interface'], ','.join(v['members'])]
                for n,v in model.vlans.items()]
        print_table("VLANs", ["Name","VLAN ID","Interface","Members"], rows)

        # Zones
        rows = [[n, ','.join(z.get('interface',[])), z.get('intrazone','N/A')]
                for n,z in model.zones.items()]
        print_table("Zones", ["Name","Interfaces","Intrazone Action"], rows)

        # Firewall Policies
        rows = [[p['id'], ','.join(p.get('srcintf',[])), ','.join(p.get('dstintf',[])),
                 ','.join(p.get('srcaddr',[])), ','.join(p.get('dstaddr',[])),
                 ','.join(p.get('service',[])), p.get('action',''),
                 p.get('status',''),
                 (f"NAT:{p.get('poolname','N/A')}" if p.get('ippool')=='enable' else \
                  f"NAT:{p.get('natip','Interface')}" if p.get('nat')=='enable' else 'No NAT'),
                 f"{p.get('av_profile','-')}/{p.get('webfilter_profile','-')}/{p.get('ips_sensor','-')}/{p.get('application_list','-')}/{p.get('ssl_ssh_profile','-')}",
                 p.get('logtraffic','off'), p.get('comments','')]
                for p in model.policies]
        print_table(
            "Firewall Policies",
            ["ID","SrcIntf","DstIntf","SrcAddr","DstAddr","Service","Action","Status","NAT","Sec Profiles (AV/WF/IPS/App/SSL)","Log","Comments"],
            rows
        )

        # Virtual IPs
        portfwd = lambda v: f"{v.get('protocol','any')}:{v.get('extport','any')}->{v.get('mappedport','any')}" \
                            if v.get('portforward') == 'enable' else 'No'
        rows = [[n, v.get('interface','any'), v.get('extip',''), v.get('mappedip',''),
                 portfwd(v), v.get('comment','')]
                for n,v in model.vips.items()]
        print_table("Virtual IPs", ["Name","Interface","ExtIP","MapIP","Port Fwd (Proto:Ext->Map)","Comment"], rows)

        # VIP Groups
        rows = [[n, ','.join(m)] for n,m in model.vip_groups.items()]
        print_table("VIP Groups", ["Name","Members"], rows)

        # IP Pools
        rows = [[n, p['startip'], p['endip'], p['type'], p['comment']]
                for n,p in model.ippools.items()]
        print_table("IP Pools", ["Name","StartIP","EndIP","Type","Comment"], rows)

        # DHCP Servers
        rows = []
        for d in model.dhcp_servers:
             # Use 'id' for Name, normalized keys, and handle interface
             interface_str = d.get('interface', '') # Should be string
             rows.append([
                 d.get('id','N/A'), # Use id from 'edit <id>'
                 interface_str,
                 d.get('lease_time',''), # Use normalized key
                 d.get('default_gateway',''), # Use normalized key
                 d.get('netmask',''),
                 d.get('ip_range',''), # Use the parsed ip_range string
                 f"{d.get('dns_server1','-')}, {d.get('dns_server2','-')}, {d.get('dns_server3','-')}, {d.get('dns_server4','-')}",
                 d.get('domain','')
              ])
        print_table("DHCP Servers", ["ID","Interface","LeaseTime","Gateway","Netmask","IPRange","DNS Servers","Domain"], rows)

        # OSPF Routers
        rows = []
        if model.ospf: # Check if OSPF config exists
            router_id = model.ospf.get('router_id', 'N/A')
            # Extract networks from the nested 'network' list if it exists
            networks = []
            if 'network' in model.ospf and isinstance(model.ospf['network'], list):
                 networks = [net.get('prefix', 'N/A') for net in model.ospf['network']]
            # Create a single row for the main OSPF process
            # Using 'OSPF Process' as a placeholder name 'n'
            rows.append(['OSPF Process', router_id, '; '.join(networks)])
        print_table("OSPF Routers", ["Name","Router ID","Networks"], rows)

        # BGP Routers
        # rows = [[n, b['as'], b['router_id']] for n,b in model.bgp.items()]
        # BGP Routers - Modified to show basic info if present
        rows = []
        if model.bgp: # Check if BGP config exists
            as_num = model.bgp.get('as', 'N/A')
            router_id = model.bgp.get('router_id', 'N/A')
            # Extract networks if parsed
            networks = []
            if 'network' in model.bgp and isinstance(model.bgp['network'], list):
                 networks = [net.get('prefix', 'N/A') for net in model.bgp['network']]
            # Placeholder name 'n'
            rows.append(['BGP Process', as_num, router_id, '; '.join(networks)])
        print_table("BGP Routers", ["Name","AS","Router ID", "Networks"], rows)

        # IPsec Phase1 Interfaces
        if model.phase1:
            # Select specific keys for clarity
            keys = ['interface', 'remote_gw', 'proposal', 'authmethod', 'dhgrp', 'keylife', 'dpd', 'status']
            rows = [[n] + [str(model.phase1[n].get(k,''))[:30] for k in keys] # Truncate long proposal strings
                    for n in sorted(model.phase1)]
            print_table("IPsec Phase1 Interfaces", ["Name"] + [k.replace('_',' ').title() for k in keys], rows)

        # IPsec Phase2 Interfaces
        if model.phase2:
            # Select specific keys
            keys = ['phase1name', 'proposal', 'pfs', 'dhgrp', 'keylifeseconds', 'src_subnet', 'dst_subnet', 'status']
            rows = [[n] + [str(model.phase2[n].get(k,''))[:30] for k in keys]
                    for n in sorted(model.phase2)]
            print_table("IPsec Phase2 Interfaces", ["Name"] + [k.replace('_',' ').title() for k in keys], rows)

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
            # Select key HA settings
            keys = ['mode', 'group_name', 'password', 'priority', 'monitor', 'hbdev', 'session_pickup', 'override', 'status']
            rows = [[k.replace('_',' ').title(), str(model.ha.get(k, 'N/A'))] for k in keys]
            print_table("High Availability Settings", ["Setting", "Value"], rows)

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
        if model.system_api_user: # Skip API Key
            keys = sorted({k for props in model.system_api_user.values() for k in props if k not in ['api_key']})
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
        # generator = NetworkDiagramGenerator(model) # Already initialized above
        generator.generate_diagram(args.output) # Pass base output name

if __name__ == '__main__':
    main()
