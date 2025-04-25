#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates network topology diagrams using Graphviz.
"""

import ipaddress
import sys
from graphviz import Digraph
# Import ConfigModel if needed for type hinting or direct access (adjust path as necessary)
# from config_model import ConfigModel 

class NetworkDiagramGenerator:
    """Generates network topology diagrams from FortiGate configuration."""
    
    def __init__(self, model):
        self.model = model # Expects an instance of ConfigModel
        self.graph = Digraph(comment='FortiGate Network Topology - Used Objects')
        self.graph.attr(rankdir='TB')  # Top to bottom layout for better network hierarchy
        self._setup_graph_attributes()
        self.address_groups_expanded = {}
        self.service_groups_expanded = {}
        self.processed_nodes = set()  # Track processed nodes to avoid duplicates

        # Sets to track used objects (populated by analyze_relationships)
        self.used_addresses = set()
        self.used_addr_groups = set()
        self.used_services = set()
        self.used_svc_groups = set()
        self.used_interfaces = set()
        self.used_zones = set()
        self.used_vips = set()
        self.used_ippools = set()
        self.used_routes = set() # Track used static routes (by generated ID)
        self.used_phase1 = set() # Track used VPN Phase 1 (by name)
        self.used_phase2 = set() # Track used VPN Phase 2 (by name)
        self.used_dhcp_servers = set() # Track used DHCP servers (by ID)

        # Sets to track unused objects (populated by _identify_unused_objects)
        self.unused_addresses = set()
        self.unused_addr_groups = set()
        self.unused_services = set()
        self.unused_svc_groups = set()
        self.unused_interfaces = set()
        self.unused_zones = set()
        self.unused_vips = set()
        self.unused_ippools = set()
        self.unused_routes = set()
        self.unused_phase1 = set()
        self.unused_phase2 = set()

        # Relationship stats (populated by analyze_relationships)
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
        
        self.ZONE_STYLE = { # Not used for nodes directly, but for cluster label styling
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
        
        self.ANY_STYLE = {
             'shape': 'ellipse', 
             'style': 'filled', 
             'fillcolor': '#bdbdbd', # Grey for 'any'
             'color': '#616161',
             'fontcolor': 'black',
             'fontsize': '8'
        }

    def _add_node(self, name, **attrs):
        """Add a node idempotently with specified attributes and default styling."""
        if name not in self.processed_nodes:
            # Basic default styling for nodes if not overridden
            default_attrs = {
                'fontname': 'Helvetica',
                'fontsize': '9',
                'margin': '0.2',
                'height': '0.4',
                'width': '1.0' # Default width
            }
            # Merge provided attrs with defaults, provided attrs take precedence
            final_attrs = {**default_attrs, **attrs}
            self.graph.node(name, **final_attrs)
            self.processed_nodes.add(name)

    def _add_edge(self, src, dst, **attrs):
        """Add an edge with specified attributes and default styling."""
        # Apply default modern styling for edges
        default_attrs = {
            'fontname': 'Helvetica',
            'fontsize': '7',
            'arrowsize': '0.7',
            'penwidth': '0.8',
            'color': '#555555'
        }
        # Merge provided attrs with defaults
        final_attrs = {**default_attrs, **attrs}
        # Ensure constraint=false edges don't affect ranking if specified
        # final_attrs['constraint'] = attrs.get('constraint', 'true') # Keep explicit constraint if provided
        self.graph.edge(src, dst, **final_attrs)

    def _get_subnet_label(self, subnet):
        """Create a concise label for a subnet node."""
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            return f"NET:\n{net.compressed}"
        except ValueError:
            # Could be FQDN, single IP, or something else
            if len(subnet) > 20: # Basic check for potentially long FQDNs
                return f"ADDR:\n{subnet[:17]}..."
            return f"ADDR:\n{subnet}"

    def _expand_address_group(self, group_name):
        """Recursively expands address groups and adds nodes/edges."""
        if group_name in self.address_groups_expanded:
            return  # Already expanded

        members = self.model.addr_groups.get(group_name, [])
        self._add_node(group_name, label=f"GRP:\n{group_name}", tooltip=f"Address Group ({len(members)} members)", **self.GROUP_STYLE)
        self.address_groups_expanded[group_name] = True

        for member in members:
            if member in self.model.addr_groups: # Nested group
                self._expand_address_group(member) # Ensure nested group node exists
                self._add_edge(group_name, member, arrowhead='empty', style='dashed', label='contains')
            elif member in self.model.addresses:
                addr_obj = self.model.addresses[member]
                label = self._get_subnet_label(addr_obj['subnet'])
                tooltip = f"Type: {addr_obj.get('type', 'N/A')}\nSubnet: {addr_obj.get('subnet', 'N/A')}\nComment: {addr_obj.get('comment', '')}"
                self._add_node(member, label=label, tooltip=tooltip, **self.NETWORK_STYLE)
                self._add_edge(group_name, member, arrowhead='empty', style='dashed', label='contains')
            else:
                print(f"Warning: Address object '{member}' referenced in group '{group_name}' not found.", file=sys.stderr)

    def _expand_service_group(self, group_name):
        """Recursively expands service groups and adds nodes/edges."""
        if group_name in self.service_groups_expanded:
            return

        members = self.model.svc_groups.get(group_name, [])
        self._add_node(group_name, label=f"SVC GRP:\n{group_name}", tooltip=f"Service Group ({len(members)} members)", **self.GROUP_STYLE)
        self.service_groups_expanded[group_name] = True

        for member in members:
            if member in self.model.svc_groups: # Nested group
                self._expand_service_group(member)
                self._add_edge(group_name, member, arrowhead='empty', style='dashed', label='contains')
            elif member in self.model.services:
                svc_obj = self.model.services[member]
                proto = svc_obj.get('protocol','?')
                port = svc_obj.get('port','any')
                label = f"SVC:\n{member}\n{proto}/{port}"
                tooltip = f"Protocol: {proto}\nPort(s): {port}\nComment: {svc_obj.get('comment', '')}"
                self._add_node(member, label=label, tooltip=tooltip, **self.SERVICE_STYLE)
                self._add_edge(group_name, member, arrowhead='empty', style='dashed', label='contains')
            else:
                print(f"Warning: Service object '{member}' referenced in group '{group_name}' not found.", file=sys.stderr) 

    def generate_zones(self):
        """Generate zone clusters and place interfaces inside them."""
        # Ensure all used interfaces are processed first (nodes created)
        self.generate_interfaces() # Creates nodes for interfaces not in zones
        
        for zone_name, zone_data in self.model.zones.items():
            if zone_name in self.used_zones:
                zone_cluster_name = f'cluster_zone_{zone_name}'
                # Create the cluster subgraph
                with self.graph.subgraph(name=zone_cluster_name) as zone_cluster:
                    zone_cluster.attr(label=f'Zone: {zone_name}', **self.CLUSTER_STYLE)
                    
                    # Add interfaces belonging to this zone inside the cluster
                    zone_interfaces = zone_data.get('interface', [])
                    for intf_name in zone_interfaces:
                        if intf_name in self.used_interfaces:
                            intf_data = self.model.interfaces.get(intf_name, {})
                            label = f"INTF:\n{intf_name}\n{intf_data.get('ip', 'DHCP/Unset')}"
                            tooltip = f"Alias: {intf_data.get('alias', 'N/A')}\nRole: {intf_data.get('role', 'N/A')}\nVDOM: {intf_data.get('vdom', 'N/A')}"
                            # Use a unique node ID within the cluster context
                            node_id = f"{zone_name}_{intf_name}" 
                            # Add node using the subgraph context
                            zone_cluster.node(node_id, label=label, tooltip=tooltip, **self.INTERFACE_STYLE)
                            self.processed_nodes.add(node_id) # Track globally as well

    def generate_address_objects(self):
        """Generate nodes for used address objects and groups."""
        # Addresses used directly
        for addr_name in self.used_addresses:
            if addr_name not in self.processed_nodes:
                 if addr_name in self.model.addresses:
                     addr_obj = self.model.addresses[addr_name]
                     label = self._get_subnet_label(addr_obj['subnet'])
                     tooltip = f"Type: {addr_obj.get('type', 'N/A')}\nSubnet: {addr_obj.get('subnet', 'N/A')}\nComment: {addr_obj.get('comment', '')}"
                     self._add_node(addr_name, label=label, tooltip=tooltip, **self.NETWORK_STYLE)
                 # else: Warning should be printed during analysis if not found

        # Address groups (expand recursively)
        for grp_name in self.used_addr_groups:
            if grp_name not in self.address_groups_expanded: # Only expand top-level used groups
                self._expand_address_group(grp_name)


    def generate_services(self):
        """Generate nodes for used service objects and groups."""
        # Services used directly
        for svc_name in self.used_services:
            if svc_name not in self.processed_nodes:
                 if svc_name in self.model.services:
                     svc_obj = self.model.services[svc_name]
                     proto = svc_obj.get('protocol','?')
                     port = svc_obj.get('port','any')
                     label = f"SVC:\n{svc_name}\n{proto}/{port}"
                     tooltip = f"Protocol: {proto}\nPort(s): {port}\nComment: {svc_obj.get('comment', '')}"
                     self._add_node(svc_name, label=label, tooltip=tooltip, **self.SERVICE_STYLE)
                 # else: Warning should be printed during analysis if not found

        # Service groups (expand recursively)
        for grp_name in self.used_svc_groups:
            if grp_name not in self.service_groups_expanded:
                self._expand_service_group(grp_name)

    def generate_routes(self):
        """Generate nodes for used static routes visually near their interfaces."""
        routes_by_interface = {}
        for route_data in self.model.routes:
             # Generate a consistent ID for the route based on its properties
             dst = route_data.get('dst', '')
             dev = route_data.get('device', '')
             gw = route_data.get('gateway', '')
             # Use seq-num if available, otherwise construct ID. Ensure uniqueness.
             route_name_or_id = route_data.get('name') or f"route_{dst}_{dev}_{gw}"
             
             if route_name_or_id in self.used_routes and dev in self.used_interfaces:
                 if dev not in routes_by_interface:
                     routes_by_interface[dev] = []
                 routes_by_interface[dev].append((route_name_or_id, route_data))

        for intf_name, routes in routes_by_interface.items():
            # Find the primary node ID for this interface (could be zone-prefixed)
            interface_node_id = self._find_interface_node_id(intf_name)
            
            if not interface_node_id:
                print(f"Warning: Interface node '{intf_name}' not found for adding routes.", file=sys.stderr)
                continue

            for route_id, route_data in routes:
                 dst = route_data.get('dst', 'N/A')
                 gw = route_data.get('gateway', 'N/A')
                 label = f"ROUTE:\n{dst}\nvia {gw}"
                 tooltip = f"ID: {route_id}\nDevice: {intf_name}\nDistance: {route_data.get('distance')}\nComment: {route_data.get('comment')}"
                 
                 self._add_node(route_id, label=label, tooltip=tooltip, **self.ROUTE_STYLE)
                 
                 # Connect route TO the interface
                 self._add_edge(route_id, interface_node_id, label='uses', style='dashed', dir='forward')

                 # Connect route to destination (if destination is a drawn node)
                 self._connect_route_to_destination(route_id, dst)

    def _connect_route_to_destination(self, route_id, destination_str):
        """Connects a route node to its destination if the destination is drawn."""
         # Resolve destination: check if it's an address object/group name first
        if destination_str in self.model.addresses or destination_str in self.model.addr_groups:
             # If the object/group node exists (was used elsewhere), connect to it
             if destination_str in self.processed_nodes:
                 self._add_edge(route_id, destination_str, label='to', style='dotted', constraint='false')
             # else: Dest object/group exists in config but wasn't used by a policy, so no node drawn.
             #       We could potentially draw it here if desired.
        else:
             # Assume it's a subnet/IP
             try:
                 # Generate the standard node ID for this subnet
                 subnet_node_id = f"net_{ipaddress.ip_network(destination_str, strict=False).compressed}"
                 # If the subnet node exists (e.g., from a direct connection), connect to it
                 if subnet_node_id in self.processed_nodes:
                     self._add_edge(route_id, subnet_node_id, label='to', style='dotted', constraint='false')
                 else:
                     # Subnet node doesn't exist. Create it now.
                     subnet_label = self._get_subnet_label(destination_str)
                     self._add_node(subnet_node_id, label=subnet_label, **self.NETWORK_STYLE)
                     self._add_edge(route_id, subnet_node_id, label='to', style='dotted', constraint='false')
             except ValueError:
                 print(f"Warning: Could not parse destination '{destination_str}' for route '{route_id}' as object or subnet.", file=sys.stderr)

    def generate_vips(self):
        """Generate nodes for used VIP objects and groups."""
        # Create a subgraph to visually group VIPs, but don't make it a cluster box
        # Subgraphs help with layout but don't draw boundaries unless styled.
        with self.graph.subgraph(name='cluster_vips') as vip_subgraph:
             vip_subgraph.attr(label='Virtual IPs', style='invis', fontname='Helvetica Bold', fontsize='11')
             
             for vip_name in self.used_vips:
                  if vip_name in self.model.vips:
                      vip_data = self.model.vips[vip_name]
                      extip = vip_data.get('extip', 'N/A')
                      mapip_list = vip_data.get('mappedip', []) # Should be a list now
                      mapip_str = ",".join(ip.get('range', '?') for ip in mapip_list) if mapip_list else 'N/A'
                      
                      portfwd_str = ""
                      if vip_data.get('portforward') == 'enable':
                          proto = vip_data.get('protocol','any')
                          extport = vip_data.get('extport','any')
                          mapport = vip_data.get('mappedport','any')
                          portfwd_str = f"\n{proto}:{extport}->{mapport}"
                      
                      label = f"VIP: {vip_name}\n{extip} -> {mapip_str}{portfwd_str}"
                      tooltip = f"Interface: {vip_data.get('interface', 'any')}\nComment: {vip_data.get('comment', '')}"
                      self._add_node(vip_name, label=label, tooltip=tooltip, **self.VIP_STYLE)

                      # Connect VIP to its mapped IP/address object if possible
                      for mapped_ip_info in mapip_list:
                          mapip = mapped_ip_info.get('range')
                          if not mapip: continue
                          
                          # Check if mapped IP string is an address object name
                          if mapip in self.model.addresses:
                              if mapip in self.processed_nodes:
                                   self._add_edge(vip_name, mapip, label='maps to', style='dashed', constraint='false')
                          elif mapip in self.model.addr_groups:
                              if mapip in self.processed_nodes:
                                  self._add_edge(vip_name, mapip, label='maps to', style='dashed', constraint='false')
                          else:
                              # Try adding as a network node if it looks like an IP/subnet
                              try:
                                   net = ipaddress.ip_network(mapip, strict=False)
                                   subnet_node_id = f"net_{net.compressed}"
                                   if subnet_node_id not in self.processed_nodes:
                                       self._add_node(subnet_node_id, label=self._get_subnet_label(mapip), **self.NETWORK_STYLE)
                                   self._add_edge(vip_name, subnet_node_id, label='maps to', style='dashed', constraint='false')
                              except ValueError:
                                  print(f"Warning: Cannot resolve or draw mapped IP '{mapip}' for VIP '{vip_name}' as object or subnet.", file=sys.stderr)
                              
             # TODO: VIP Groups - if needed, similar expansion logic

    def generate_ip_pools(self):
        """Generate nodes for used IP Pool objects."""
        with self.graph.subgraph(name='cluster_ippools') as pool_subgraph:
             pool_subgraph.attr(label='IP Pools', style='invis', fontname='Helvetica Bold', fontsize='11')
             for pool_name in self.used_ippools:
                  if pool_name in self.model.ippools:
                      pool_data = self.model.ippools[pool_name]
                      label = f"POOL: {pool_name}\n{pool_data.get('startip', '?')} - {pool_data.get('endip', '?')}"
                      tooltip = f"Type: {pool_data.get('type', 'N/A')}\nComment: {pool_data.get('comment', '')}"
                      self._add_node(pool_name, label=label, tooltip=tooltip, **self.POOL_STYLE)

    def _create_cluster(self, name, label):
        """Helper to create a styled subgraph cluster context."""
        # This returns the subgraph object itself, use with `with` statement
        # The caller will add nodes/edges using the cluster object.
        cluster = Digraph(name)
        cluster.attr(label=label, **self.CLUSTER_STYLE)
        # Add the subgraph to the main graph *before* returning context
        self.graph.subgraph(cluster)
        return cluster

    def _create_subgraph(self, parent, name, label):
        """Helper to create a styled subgraph (non-cluster for grouping)."""
        # This returns the subgraph object itself, use with `with` statement
        subgraph = Digraph(name)
        subgraph.attr(
            label=label,
            style='invis', # No box around the subgraph itself
            fontname='Helvetica Bold',
            fontsize='11',
            margin='10' # Adjust spacing around the subgraph label
        )
        parent.subgraph(subgraph) # Add subgraph to the parent graph
        return subgraph
        
    def _find_interface_node_id(self, intf_name):
        """Finds the correct graph node ID for an interface, considering zones."""
        # Check if it's drawn inside a zone first
        for zone_name in self.used_zones:
            zone_intf_id = f"{zone_name}_{intf_name}"
            if zone_intf_id in self.processed_nodes:
                 return zone_intf_id
        # If not in a zone, check if it exists as a top-level node
        if intf_name in self.processed_nodes:
             return intf_name
        # Interface node wasn't found/drawn
        return None

    def generate_network_hierarchy(self):
        """Generate hierarchical view: Zones -> Interfaces -> Connected Networks/Routes."""
        # 1. Generate Zone Clusters (implicitly generates interfaces inside)
        self.generate_zones()
        
        # 2. Explicitly generate any used interfaces NOT in a used zone
        #    (generate_interfaces() was called by generate_zones)
        
        # 3. Connect Interfaces to their directly connected networks (based on IP/mask)
        for intf_name, intf_data in self.model.interfaces.items():
            if intf_name in self.used_interfaces and 'ip' in intf_data and '/' in intf_data['ip']:
                interface_node_id = self._find_interface_node_id(intf_name)
                if interface_node_id: # Ensure interface node exists
                    try:
                        iface = ipaddress.ip_interface(intf_data['ip'])
                        network = iface.network
                        net_label = self._get_subnet_label(str(network))
                        net_node_id = f"net_{network.compressed}" # Unique ID for network node
                        
                        # Add network node if it doesn't exist
                        if net_node_id not in self.processed_nodes:
                            self._add_node(net_node_id, label=net_label, tooltip=f"Connected to {intf_name}", **self.NETWORK_STYLE)
                        # Add edge from interface to its network
                        self._add_edge(interface_node_id, net_node_id, arrowhead='none', style='bold')
                    except ValueError as e:
                        print(f"Warning: Could not parse IP for interface '{intf_name}': {intf_data['ip']} - {e}", file=sys.stderr)
                    
        # 4. Add routes (visually connected to interfaces and destinations)
        #    This should happen after interfaces and potential destination networks are drawn.
        self.generate_routes()

    def generate_security_configuration(self):
        """Generate nodes related to security policies, objects, and services."""
        # 1. Generate Address Objects and Groups (will be connected later by policies)
        self.generate_address_objects()

        # 2. Generate Service Objects and Groups (will be connected later by policies)
        self.generate_services()

        # 3. Generate Firewall Policies (nodes only, connections handled separately)
        with self.graph.subgraph(name='cluster_policies') as policy_subgraph:
             policy_subgraph.attr(label='Firewall Policies', style='invis', fontname='Helvetica Bold', fontsize='11')
             for policy_data in self.model.policies:
                 policy_id_num = policy_data['id']
                 policy_id = f"pol_{policy_id_num}"
                 if policy_id in self.processed_nodes: # Only add if it was marked as used
                     action = policy_data.get('action','N/A')
                     label = f"Policy {policy_id_num}\nAction: {action}"
                     # Build a comprehensive tooltip
                     tooltip_parts = [
                         f"ID: {policy_id_num}",
                         f"Status: {policy_data.get('status','N/A')}",
                         f"Action: {action}",
                         f"Src Intf: {', '.join(policy_data.get('srcintf',[]))}",
                         f"Dst Intf: {', '.join(policy_data.get('dstintf',[]))}",
                         f"Src Addr: {', '.join(policy_data.get('srcaddr',[]))}",
                         f"Dst Addr: {', '.join(policy_data.get('dstaddr',[]))}",
                         f"Service: {', '.join(policy_data.get('service',[]))}",
                     ]
                     if policy_data.get('nat') == 'enable':
                         nat_str = "NAT: Outgoing IF IP"
                         if policy_data.get('ippool') == 'enable':
                             nat_str = f"NAT Pool: {policy_data.get('poolname', '-')}"
                         tooltip_parts.append(nat_str)
                     if policy_data.get('comments'):
                         tooltip_parts.append(f"Comment: {policy_data['comments']}")
                         
                     tooltip = "\n".join(tooltip_parts)
                     # Add policy node within the policy subgraph
                     self._add_node(policy_id, label=label, tooltip=tooltip, **self.POLICY_STYLE)

    def generate_nat_configuration(self):
        """Generate nodes and connections related to NAT (VIPs, IP Pools)."""
        # 1. Generate VIP nodes (if used)
        self.generate_vips() 
        
        # 2. Generate IP Pool nodes (if used)
        self.generate_ip_pools()
        
        # 3. Connect policies to IP Pools if NAT pool is used
        for policy_data in self.model.policies:
            policy_id_num = policy_data['id']
            policy_id = f"pol_{policy_id_num}"
            if policy_id in self.processed_nodes: # If policy node exists
                if policy_data.get('ippool') == 'enable' and 'poolname' in policy_data:
                    pool_name = policy_data['poolname']
                    if pool_name in self.used_ippools and pool_name in self.processed_nodes:
                        # Connect policy to the pool node
                        self._add_edge(policy_id, pool_name, label='uses NAT pool', style='dashed', color='#78909c', constraint='false')
                    # else: Warning should have been printed during analysis

    def generate_sd_wan(self):
        """Generate SD-WAN related nodes and connections."""
        # Check if sd_wan configuration exists and has members or services
        has_sdwan_config = self.model.sd_wan and (
            self.model.sd_wan.get('members') or self.model.sd_wan.get('service')
        )
        if not has_sdwan_config:
            return

        with self._create_cluster(f'cluster_sdwan', 'SD-WAN') as sdwan_cluster:
            sdwan_main_node_id = 'sdwan_logic' # Represent the core SD-WAN logic
            sdwan_cluster.node(sdwan_main_node_id, label='SD-WAN\nLogic', tooltip='SD-WAN Configuration', **self.SD_WAN_STYLE)
            self.processed_nodes.add(sdwan_main_node_id)
            
            # SD-WAN Members (Interfaces)
            members = self.model.sd_wan.get('members', [])
            if isinstance(members, list):
                 for member in members:
                     intf_name = member.get('interface')
                     if intf_name in self.used_interfaces:
                         interface_node_id = self._find_interface_node_id(intf_name)
                         if interface_node_id:
                            # Connect the SD-WAN logic node to the member interface
                            gw = member.get('gateway', 'N/A')
                            priority = member.get('priority', 'N/A')
                            tooltip = f"SD-WAN Member\nInterface: {intf_name}\nGateway: {gw}\nPriority: {priority}"
                            # Edge from interface TO sd-wan logic node, indicating participation
                            self._add_edge(interface_node_id, sdwan_main_node_id, label='member', tooltip=tooltip, style='bold', color='#7cb342')
            
            # SD-WAN Rules (Policies/Services)
            rules = self.model.sd_wan.get('service', [])
            if isinstance(rules, list):
                for rule in rules:
                    rule_id_num = rule.get('id')
                    rule_name = rule.get('name', f'Rule {rule_id_num}')
                    rule_node_id = f"sdwan_rule_{rule_id_num}"
                    label = f"SD-WAN Rule:\n{rule_name}"
                    tooltip = f"ID: {rule_id_num}\nName: {rule_name}\nMode: {rule.get('mode', '?')}\nInput: {rule.get('input_device', '?')}"
                    # Add SD-WAN rule node inside the cluster
                    sdwan_cluster.node(rule_node_id, label=label, tooltip=tooltip, **self.POLICY_STYLE) # Reuse policy style
                    self.processed_nodes.add(rule_node_id)
                    
                    # Connect rule to the main SD-WAN logic node
                    self._add_edge(sdwan_main_node_id, rule_node_id, label='contains rule', style='dotted', dir='none')
                    
                    # Optional: Connect rule to its destination addresses/services if drawn
                    # Example for destination address:
                    # for addr_name in rule.get('dst', []):
                    #      if addr_name in self.processed_nodes:
                    #           self._add_edge(rule_node_id, addr_name, label='to', style='dotted', constraint='false')
                    # Example for output devices (preferred members):
                    # for member_pref in rule.get('priority_members', []):
                         # Find interface node for member_pref (seq num?) -> needs mapping
                         # member_intf_node = ...
                         # if member_intf_node:
                         #      self._add_edge(rule_node_id, member_intf_node, label='prefers', style='dotted', constraint='false')

    def generate_vpn_tunnels(self):
        """Generate nodes and connections for used IPsec VPN tunnels."""
        # Determine which tunnels are actually used (via policies referencing them)
        used_tunnel_names = set(self.used_phase1) # Start with P1 tunnels directly referenced
        
        if not used_tunnel_names:
            return # Skip if no VPN tunnels are used

        with self._create_cluster(f'cluster_vpn', 'IPsec VPN Tunnels') as vpn_cluster:
            for tunnel_name in used_tunnel_names:
                if tunnel_name in self.model.phase1:
                    p1_data = self.model.phase1[tunnel_name]
                    local_gw_intf = p1_data.get('interface')
                    remote_gw = p1_data.get('remote_gw')
                    label = f"VPN Tunnel:\n{tunnel_name}"
                    tooltip = f"Phase 1: {tunnel_name}\nLocal IF: {local_gw_intf}\nRemote GW: {remote_gw}\nProposal: {p1_data.get('proposal', '?')}"
                    
                    # Add Phase 1 node (representing the tunnel interface)
                    self._add_node(tunnel_name, label=label, tooltip=tooltip, **self.VPN_STYLE)
                    # self.processed_nodes is updated by _add_node
                    
                    # Connect Phase 1 to its underlying local physical interface if used
                    if local_gw_intf in self.used_interfaces:
                        interface_node_id = self._find_interface_node_id(local_gw_intf)
                        if interface_node_id:
                            self._add_edge(tunnel_name, interface_node_id, label='uses physical IF', style='dashed')
                            
                    # Find and add associated Phase 2 selectors (if P2 name is marked as used)
                    for p2_name, p2_data in self.model.phase2.items():
                         if p2_data.get('phase1name') == tunnel_name and p2_name in self.used_phase2:
                             p2_node_id = f"p2_{p2_name}" # Unique ID for P2 node
                             # Format selector info carefully (can be object names or subnets)
                             src_sel = p2_data.get('src_subnet') or p2_data.get('src_addr_type') # TODO: Refine based on parsed data
                             dst_sel = p2_data.get('dst_subnet') or p2_data.get('dst_addr_type')
                             p2_label = f"P2: {p2_name}\nSrc: {src_sel}\nDst: {dst_sel}"
                             tooltip = f"Phase 2: {p2_name}\nProposal: {p2_data.get('proposal', '?')}\nPFS: {p2_data.get('pfs', 'disable')}"
                             # Add Phase 2 node inside the VPN cluster
                             vpn_cluster.node(p2_node_id, label=p2_label, tooltip=tooltip, **self.VPN_STYLE)
                             self.processed_nodes.add(p2_node_id)
                             # Connect P1 tunnel node to P2 selector node
                             self._add_edge(tunnel_name, p2_node_id, label='defines policy', style='dotted', dir='none')
                             
                             # Optional: Connect P2 node to actual src/dst address objects if they are drawn
                             # self._connect_p2_selectors(p2_node_id, src_sel, dst_sel)

    def generate_interfaces(self):
        """Generate nodes for used interfaces NOT already handled by generate_zones."""
        # This function ensures interface nodes are created *before* they are potentially
        # placed inside zone clusters or referenced by other elements like routes.
        for intf_name, intf_data in self.model.interfaces.items():
            if intf_name in self.used_interfaces:
                # Check if it's already processed (likely within a zone)
                node_id = self._find_interface_node_id(intf_name)
                if not node_id:
                    # Interface is used but not in a used zone and not yet drawn.
                    # Create it in the main graph.
                    label = f"INTF:\n{intf_name}\n{intf_data.get('ip', 'DHCP/Unset')}"
                    tooltip = f"Alias: {intf_data.get('alias', 'N/A')}\nRole: {intf_data.get('role', 'N/A')}\nVDOM: {intf_data.get('vdom', 'N/A')}"
                    self._add_node(intf_name, label=label, tooltip=tooltip, **self.INTERFACE_STYLE)

    def generate_policies(self):
        """Generate policy nodes and connect them to relevant elements."""
        # First, ensure policy nodes themselves are created (if used)
        # This is now handled by generate_security_configuration
        self.generate_security_configuration() 

        # Now, connect the policies to interfaces, zones, addresses, services, VIPs
        for policy_data in self.model.policies:
            policy_id_num = policy_data['id']
            policy_id = f"pol_{policy_id_num}"
            if policy_id in self.processed_nodes: # Only connect policies that were drawn
                
                # Connect Policy -> Interfaces/Zones/Tunnels (Source and Destination)
                self._connect_policy_endpoints(policy_data, 'src', policy_id)
                self._connect_policy_endpoints(policy_data, 'dst', policy_id)
                
                # Connect Policy -> Address Objects/Groups/VIPs (Source and Destination)
                self._connect_policy_addresses(policy_data, 'src', policy_id)
                self._connect_policy_addresses(policy_data, 'dst', policy_id)
                
                # Connect Policy -> Services/Service Groups
                self._connect_policy_services(policy_data, policy_id)
                
                # Connect Policy -> NAT Pools (Handled in generate_nat_configuration)

    def _connect_policy_endpoints(self, policy_data, direction, policy_id):
        """Connects a policy node to its source/destination interfaces, zones, or tunnels."""
        intf_key = f'{direction}intf' # srcintf or dstintf
        edge_label_intf = f'{direction.upper()} Intf'
        edge_label_zone = f'{direction.upper()} Zone'
        edge_label_vpn = f'{direction.upper()} VPN'
        color = '#4285f4' if direction == 'src' else '#34a853' # Blue for src, Green for dst

        for element_name in policy_data.get(intf_key, []):
            target_node_id = None
            edge_label = edge_label_intf # Default label
            conn_color = color
            
            # 1. Check if it's a Zone
            if element_name in self.used_zones and element_name in self.model.zones:
                # Find the first *drawn* interface within that zone to connect to.
                # This provides a visual link without connecting directly to cluster boundary.
                zone_interfaces = self.model.zones[element_name].get('interface', [])
                for intf_in_zone in zone_interfaces:
                     potential_node_id = f"{element_name}_{intf_in_zone}"
                     if potential_node_id in self.processed_nodes:
                          target_node_id = potential_node_id
                          edge_label = edge_label_zone
                          break # Connect to first found interface in the zone
                if not target_node_id:
                     print(f"Warning: Could not find a drawn interface in zone '{element_name}' to connect policy {policy_data['id']}.")
                     continue 
            
            # 2. Check if it's a used Interface (not already handled by zone)
            elif target_node_id is None and element_name in self.used_interfaces and element_name in self.model.interfaces:
                target_node_id = self._find_interface_node_id(element_name)
                if not target_node_id:
                     print(f"Warning: Interface '{element_name}' used by policy {policy_data['id']} not found in processed nodes.")
                     continue
            
            # 3. Check if it's a used VPN Tunnel (Phase 1 name)
            elif target_node_id is None and element_name in self.used_phase1 and element_name in self.model.phase1:
                 target_node_id = element_name # VPN P1 node uses the tunnel name as ID
                 if target_node_id not in self.processed_nodes:
                     print(f"Warning: VPN Tunnel '{element_name}' used by policy {policy_data['id']} not found in processed nodes.")
                     continue
                 edge_label = edge_label_vpn
                 conn_color = '#26a69a' # Use VPN color
            
            # 4. Element not found or not used
            elif target_node_id is None:
                # print(f"Debug: Element '{element_name}' in {intf_key} of policy {policy_data['id']} is not a drawn zone, interface, or tunnel.")
                continue

            # Add the edge
            if direction == 'src':
                 self._add_edge(target_node_id, policy_id, label=edge_label, color=conn_color)
            else: # dst
                 self._add_edge(policy_id, target_node_id, label=edge_label, color=conn_color)

    def _connect_policy_addresses(self, policy_data, direction, policy_id):
        """Connects a policy node to its source/destination addresses, groups, or VIPs."""
        addr_key = f'{direction}addr' # srcaddr or dstaddr
        edge_label = f'{direction.upper()} Addr'
        color = '#ea4335' if direction == 'src' else '#fbbc05' # Red for src, Yellow for dst
        vip_color = '#ab47bc' # Purple for VIPs
        any_color = '#bdbdbd' # Grey for Any

        for addr_name in policy_data.get(addr_key, []):
            target_node_id = None
            conn_color = color # Default color
            
            # Handle 'all' / 'any' case
            if addr_name.lower() == 'all' or addr_name.lower() == 'any':
                 target_node_id = "any_address"
                 if target_node_id not in self.processed_nodes:
                      self._add_node(target_node_id, label="ANY", **self.ANY_STYLE)
                 conn_color = any_color
            # Check if it's a VIP (only relevant for destination)
            elif direction == 'dst' and addr_name in self.used_vips:
                 target_node_id = addr_name
                 edge_label = 'to VIP'
                 conn_color = vip_color
            # Check if it's a used Address Object or Group
            elif addr_name in self.used_addresses or addr_name in self.used_addr_groups:
                 target_node_id = addr_name
            else:
                # Address object exists in config but wasn't marked as used elsewhere
                # Or it doesn't exist at all (warning printed during analysis)
                # print(f"Debug: Address/Group '{addr_name}' in {addr_key} of policy {policy_data['id']} not found in processed nodes.")
                continue
            
            # Ensure target node actually exists in the graph
            if target_node_id not in self.processed_nodes:
                 # print(f"Debug: Target node '{target_node_id}' for policy {policy_data['id']} address connection not found.")
                 continue
                 
            # Add the edge
            if direction == 'src':
                 self._add_edge(target_node_id, policy_id, label=edge_label, style='dotted', color=conn_color, constraint='false')
            else: # dst
                 self._add_edge(policy_id, target_node_id, label=edge_label, style='dotted', color=conn_color, constraint='false')

    def _connect_policy_services(self, policy_data, policy_id):
        """Connects a policy node to its services/service groups."""
        svc_key = 'service'
        edge_label = 'Allows Svc'
        color = '#5c6bc0' # Service color (blue/purple)
        any_color = '#bdbdbd' # Grey for Any
        
        for svc_name in policy_data.get(svc_key, []):
            target_node_id = None
            conn_color = color
            
            # Handle 'ALL' / 'ANY' case
            if svc_name.upper() == 'ALL' or svc_name.upper() == 'ANY':
                 target_node_id = "any_service"
                 if target_node_id not in self.processed_nodes:
                      self._add_node(target_node_id, label="ANY Svc", **self.ANY_STYLE)
                 conn_color = any_color
            # Check if it's a used Service Object or Group
            elif svc_name in self.used_services or svc_name in self.used_svc_groups:
                 target_node_id = svc_name
            else:
                # Service object exists but wasn't marked used, or doesn't exist
                # print(f"Debug: Service/Group '{svc_name}' in {svc_key} of policy {policy_data['id']} not found in processed nodes.")
                continue
                
            # Ensure target node exists
            if target_node_id not in self.processed_nodes:
                # print(f"Debug: Target service node '{target_node_id}' for policy {policy_data['id']} connection not found.")
                 continue
                 
            # Add the edge (Policy -> Service)
            self._add_edge(policy_id, target_node_id, label=edge_label, style='dotted', color=conn_color, constraint='false') 

    # --- Analysis Methods --- 

    def analyze_relationships(self):
        """Analyze relationships between objects to identify used components before drawing."""
        print("Analyzing configuration relationships to identify used objects...")
        
        # Reset used sets before analysis
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
        self.processed_nodes = set() # Reset nodes intended for the final graph
        # Reset relationship counts
        self.relationship_stats = {k: {} for k in self.relationship_stats}
        
        # --- Identify objects used by Firewall Policies ---
        policy_ids_using_tunnels = set()
        for policy_data in self.model.policies:
            policy_id_num = policy_data['id']
            policy_id_node = f"pol_{policy_id_num}" # Node ID for the policy
            is_enabled = policy_data.get('status', 'enable') == 'enable'
            is_referenced = False # Does this policy reference any specific, known objects?

            # 1. Check Interfaces/Zones/Tunnels
            policy_endpoints = set()
            for intf_key in ['srcintf', 'dstintf']:
                for element_name in policy_data.get(intf_key, []):
                     policy_endpoints.add(element_name)
                     if element_name in self.model.zones:
                         self.used_zones.add(element_name)
                         is_referenced = True
                         # Mark interfaces within the zone as used
                         for zone_intf in self.model.zones[element_name].get('interface',[]):
                              if zone_intf in self.model.interfaces:
                                  self.used_interfaces.add(zone_intf)
                     elif element_name in self.model.interfaces:
                         self.used_interfaces.add(element_name)
                         is_referenced = True
                     elif element_name in self.model.phase1:
                          self.used_phase1.add(element_name) # Mark the P1 tunnel as used
                          is_referenced = True
                          policy_ids_using_tunnels.add(policy_id_num)
                          # Mark the P1's underlying physical interface as used
                          phy_intf = self.model.phase1[element_name].get('interface')
                          if phy_intf and phy_intf in self.model.interfaces:
                              self.used_interfaces.add(phy_intf)
                     # else: Interface/Zone/Tunnel not found in config (warning later if needed)
            
            # 2. Check Addresses/Groups/VIPs
            policy_addresses = set()
            for addr_key in ['srcaddr', 'dstaddr']:
                for addr_name in policy_data.get(addr_key, []):
                    # --- DEBUG START: Check type of addr_name --- 
                    if not isinstance(addr_name, str):
                         print(f"ERROR analyze_relationships: Policy {policy_id_num} has non-string element in '{addr_key}': {addr_name} (Type: {type(addr_name)})", file=sys.stderr)
                         continue # Skip this problematic element
                    # --- DEBUG END ---
                    policy_addresses.add(addr_name)
                    self._add_used_address_recursive(addr_name) # Mark recursively
                    # Check if it's a specific reference (not 'all'/'any')
                    if addr_name.lower() != 'all' and addr_name.lower() != 'any':
                        is_referenced = True # References a specific address/group/vip

            # 3. Check Services/Groups
            policy_services = set()
            for svc_name in policy_data.get('service', []):
                policy_services.add(svc_name)
                self._add_used_service_recursive(svc_name) # Mark recursively
                if svc_name.upper() != 'ALL' and svc_name.upper() != 'ANY':
                     is_referenced = True # References a specific service/group

            # 4. Check IP Pools
            if policy_data.get('ippool') == 'enable' and 'poolname' in policy_data:
                pool_name = policy_data['poolname']
                if pool_name in self.model.ippools:
                    self.used_ippools.add(pool_name)
                    is_referenced = True # Using NAT pool makes policy relevant
                else:
                    print(f"Warning: IP Pool '{pool_name}' referenced in policy {policy_id_num} not found.", file=sys.stderr)
            
            # Mark the policy node itself for drawing if it's enabled and references something specific
            if is_enabled and is_referenced:
                self.processed_nodes.add(policy_id_node)
                # Update relationship counts for summary
                for endpoint in policy_endpoints: # Count refs per IF/Zone/Tunnel
                    self.relationship_stats['interface_policy_count'][endpoint] = self.relationship_stats['interface_policy_count'].get(endpoint, 0) + 1
                for addr in policy_addresses: # Count refs per Addr/Group/VIP
                    # --- DEBUG START: Check type of addr --- 
                    if not isinstance(addr, str):
                         print(f"ERROR analyze_relationships: policy_addresses set contains non-string: {addr} (Type: {type(addr)}) while processing Policy {policy_id_num}", file=sys.stderr)
                         continue # Skip this problematic element
                    # --- DEBUG END ---
                    if addr.lower() not in ['all', 'any']:
                         self.relationship_stats['address_policy_count'][addr] = self.relationship_stats['address_policy_count'].get(addr, 0) + 1
                for svc in policy_services: # Count refs per Svc/Group
                     # Check type for service just in case
                     if not isinstance(svc, str):
                          print(f"ERROR analyze_relationships: policy_services set contains non-string: {svc} (Type: {type(svc)}) while processing Policy {policy_id_num}", file=sys.stderr)
                          continue # Skip this problematic element
                     if svc.upper() not in ['ALL', 'ANY']:
                          self.relationship_stats['service_policy_count'][svc] = self.relationship_stats['service_policy_count'].get(svc, 0) + 1

        # --- Mark Phase 2 based on used Phase 1 tunnels ---
        for p2_name, p2_data in self.model.phase2.items():
             p1_ref = p2_data.get('phase1name')
             if p1_ref in self.used_phase1:
                 self.used_phase2.add(p2_name)
                 # Also mark selectors as used if they are address objects/groups
                 src_sel = p2_data.get('src_subnet') or p2_data.get('src_addr_type')
                 dst_sel = p2_data.get('dst_subnet') or p2_data.get('dst_addr_type')
                 if src_sel: self._add_used_address_recursive(src_sel)
                 if dst_sel: self._add_used_address_recursive(dst_sel)

        # --- Identify interfaces used by Static Routes ---
        for route_data in self.model.routes:
             dev = route_data.get('device')
             # Only consider routes whose egress interface is used by policies/VPNs/etc.
             if dev and dev in self.used_interfaces:
                 dst = route_data.get('dst', '')
                 gw = route_data.get('gateway', '')
                 route_id = route_data.get('name') or f"route_{dst}_{dev}_{gw}"
                 self.used_routes.add(route_id) 
                 # Mark the destination address/subnet as potentially used if it's an object/group
                 if dst:
                     self._add_used_address_recursive(dst)
             # else: Route exists but its interface isn't used by anything else considered

        # --- Identify interfaces used by DHCP Servers (optional, for context) ---
        for dhcp_data in self.model.dhcp_servers:
            intf_name = dhcp_data.get('interface')
            dhcp_id = dhcp_data.get('id')
            if intf_name in self.used_interfaces and dhcp_id:
                self.used_dhcp_servers.add(dhcp_id)
                # Note: We don't draw DHCP servers by default, just track usage.

        # --- Interfaces used by VIPs/SD-WAN/VPNs already handled above ---
        
        # --- Final cleanup: Ensure all interfaces within used zones are marked as used ---
        # (This was already done when processing policies referencing zones)

        # --- Calculate Group Depths (for relationship summary) ---
        self.relationship_stats['address_group_depth'] = self._analyze_group_depth('address')
        self.relationship_stats['service_group_depth'] = self._analyze_group_depth('service')
        
        # --- Identify Unused Objects ---
        self._identify_unused_objects() # Populates self.unused_* sets

        print(f"Analysis complete. Identified {len(self.processed_nodes)} policy nodes to draw.")
        print(f"Total Used - Intf: {len(self.used_interfaces)}, Zone: {len(self.used_zones)}, Addr: {len(self.used_addresses)}, AddrGrp: {len(self.used_addr_groups)}")
        print(f"Total Used - Svc: {len(self.used_services)}, SvcGrp: {len(self.used_svc_groups)}, VIP: {len(self.used_vips)}, Pool: {len(self.used_ippools)}, Route: {len(self.used_routes)}, VPN P1: {len(self.used_phase1)}")

    def _add_used_address_recursive(self, name):
        """Recursively mark address objects, groups, VIPs, and their components as used."""
        # --- FIX START: Check if name is actually a list (e.g., from route dest or p2 selector) ---
        if not isinstance(name, str):
            # If it's a list like ['ip', 'mask'] or just not a string, 
            # it's not a named object/group we need to track recursively here.
            # Silently return without processing or erroring.
            # print(f"DEBUG _add_used_address_recursive: Skipping non-string input: {name} (Type: {type(name)})", file=sys.stderr)
            return
        # --- FIX END ---
        
        # Original check for string keywords
        if name.lower() in ['all', 'any']: return # Ignore generic keywords
        
        processed_locally = set() # Avoid infinite recursion within this call stack
        
        def mark_used(item_name, visited):
            # --- FIX START: Add check inside recursive helper too ---
            if not isinstance(item_name, str):
                # print(f"DEBUG mark_used: Skipping non-string item_name: {item_name} (Type: {type(item_name)})", file=sys.stderr)
                return 
            # --- FIX END ---
            
            if item_name in visited: return
            visited.add(item_name)
            
            # Original logic
            if item_name in self.model.addresses:
                self.used_addresses.add(item_name)
                # Mark associated interface if defined
                assoc_intf = self.model.addresses[item_name].get('associated_interface')
                if assoc_intf and assoc_intf in self.model.interfaces:
                     self.used_interfaces.add(assoc_intf)
            elif item_name in self.model.addr_groups:
                self.used_addr_groups.add(item_name)
                for member in self.model.addr_groups[item_name]:
                     mark_used(member, visited.copy()) # Recurse
            elif item_name in self.model.vips: 
                self.used_vips.add(item_name)
                vip_data = self.model.vips[item_name]
                # Mark VIP's interface if defined
                vip_intf = vip_data.get('interface', 'any')
                if vip_intf != 'any' and vip_intf in self.model.interfaces:
                     self.used_interfaces.add(vip_intf)
                # Mark VIP's mapped IP(s) as used
                for mapped_ip_info in vip_data.get('mappedip', []):
                    mapip = mapped_ip_info.get('range')
                    if mapip:
                        mark_used(mapip, visited.copy()) # Recurse on mapped IP/Object
            # else: Item not found (warning printed elsewhere if needed)
            
        mark_used(name, processed_locally)

    def _add_used_service_recursive(self, name):
        """Recursively mark service objects and groups as used."""
        if name.upper() in ['ALL', 'ANY']: return
        
        processed_locally = set()
        
        def mark_used(item_name, visited):
            if item_name in visited: return
            visited.add(item_name)

            if item_name in self.model.services:
                 self.used_services.add(item_name)
            elif item_name in self.model.svc_groups:
                 self.used_svc_groups.add(item_name)
                 for member in self.model.svc_groups[item_name]:
                      mark_used(member, visited.copy())
            # else: Item not found
            
        mark_used(name, processed_locally)

    def _analyze_group_depth(self, group_type):
        """Calculate the maximum nesting depth for address or service groups."""
        depths = {}
        max_depth_overall = 0
        visited_calc = {} # Memoization for calculated depths

        if group_type == 'address':
            groups = self.model.addr_groups
            items = self.model.addresses
        elif group_type == 'service':
            groups = self.model.svc_groups
            items = self.model.services
        else:
            return {}, 0
            
        def calculate_depth(name, visited_path):
            if name in visited_calc: return visited_calc[name] # Return memoized result
            if name in visited_path: return -1 # Cycle detected
            
            visited_path.add(name)
            current_max_depth = 0
            is_base_item = False
            
            if name in groups:
                members = groups.get(name, [])
                if not members: # Empty group
                     current_max_depth = 1
                else:
                    max_member_depth = 0
                    for member in members:
                        member_depth = calculate_depth(member, visited_path.copy())
                        if member_depth == -1: # Cycle detected below
                             visited_path.remove(name) # Backtrack
                             visited_calc[name] = -1 # Memoize cycle result
                             return -1 # Propagate cycle detection up
                        max_member_depth = max(max_member_depth, member_depth)
                    current_max_depth = max_member_depth + 1
            elif name in items:
                is_base_item = True
                current_max_depth = 1 # Base item has depth 1
            else:
                # Item not found (e.g., built-in like 'all', VIP name, or error)
                # Treat these as having depth 0 for calculation purposes
                current_max_depth = 0 

            visited_path.remove(name) # Backtrack
            visited_calc[name] = current_max_depth # Memoize result
            return current_max_depth

        # Calculate depth for all defined groups
        for group_name in groups.keys():
            if group_name not in visited_calc:
                 depth = calculate_depth(group_name, set())
                 depths[group_name] = depth if depth != -1 else 'Cycle Detected'
                 if isinstance(depth, int) and depth > max_depth_overall:
                     max_depth_overall = depth
        
        # print(f"DEBUG: Max {group_type} group depth: {max_depth_overall}")
        # print(f"DEBUG: {group_type} Depths: {depths}")
        return depths

    def _identify_unused_objects(self):
        """Compare all defined objects against the sets of used objects."""
        self.unused_addresses = set(self.model.addresses.keys()) - self.used_addresses
        self.unused_addr_groups = set(self.model.addr_groups.keys()) - self.used_addr_groups
        self.unused_services = set(self.model.services.keys()) - self.used_services
        self.unused_svc_groups = set(self.model.svc_groups.keys()) - self.used_svc_groups
        self.unused_interfaces = set(self.model.interfaces.keys()) - self.used_interfaces
        self.unused_zones = set(self.model.zones.keys()) - self.used_zones
        self.unused_vips = set(self.model.vips.keys()) - self.used_vips
        self.unused_ippools = set(self.model.ippools.keys()) - self.used_ippools
        
        # Identify unused routes based on the generated IDs
        defined_route_ids = set()
        for r in self.model.routes:
             dst = r.get('dst', '')
             dev = r.get('device', '')
             gw = r.get('gateway', '')
             route_id = r.get('name') or f"route_{dst}_{dev}_{gw}"
             defined_route_ids.add(route_id)
        self.unused_routes = defined_route_ids - self.used_routes
        
        self.unused_phase1 = set(self.model.phase1.keys()) - self.used_phase1
        self.unused_phase2 = set(self.model.phase2.keys()) - self.used_phase2
        
        # Filter out potentially built-in or virtual objects heuristically
        built_ins_addr = {'all', 'any', 'none'} # Common keywords
        built_ins_svc = {'all', 'any', 'ping', 'http', 'https', 'ssh', 'telnet', 'ftp', 'dns', 'smtp', 'pop3', 'imap', 'snmp', 'syslog'} # Common built-in services
        virtual_intf_patterns = ['ssl.', 'loopback', 'ipsec', 'tunnel', 'vlan'] # Prefixes/names of virtual interfaces

        # --- MODIFICATION START: Add type checks ---
        filtered_unused_addresses = set()
        for addr in self.unused_addresses:
            if isinstance(addr, str):
                if addr.lower() not in built_ins_addr:
                    filtered_unused_addresses.add(addr)
            else:
                print(f"Warning [_identify_unused_objects]: Found non-string key in addresses: {addr} (type: {type(addr)}). Skipping.", file=sys.stderr)
        self.unused_addresses = filtered_unused_addresses
        
        filtered_unused_services = set()
        for svc in self.unused_services:
            if isinstance(svc, str):
                 if svc.lower() not in built_ins_svc:
                      filtered_unused_services.add(svc)
            else:
                print(f"Warning [_identify_unused_objects]: Found non-string key in services: {svc} (type: {type(svc)}). Skipping.", file=sys.stderr)
        self.unused_services = filtered_unused_services

        filtered_unused_interfaces = set()
        for intf in self.unused_interfaces:
            if isinstance(intf, str):
                 if not any(intf.lower().startswith(p) for p in virtual_intf_patterns):
                      filtered_unused_interfaces.add(intf)
            else:
                print(f"Warning [_identify_unused_objects]: Found non-string key in interfaces: {intf} (type: {type(intf)}). Skipping.", file=sys.stderr)
        self.unused_interfaces = filtered_unused_interfaces
        # --- MODIFICATION END ---

        # Original list comprehensions replaced by the loops above:
        # self.unused_addresses = {addr for addr in self.unused_addresses if addr.lower() not in built_ins_addr}
        # self.unused_services = {svc for svc in self.unused_services if svc.lower() not in built_ins_svc}
        # self.unused_interfaces = {intf for intf in self.unused_interfaces 
        #                          if not any(intf.lower().startswith(p) for p in virtual_intf_patterns)}

        # print(f"DEBUG Unused - Addr: {len(self.unused_addresses)}, AddrGrp: {len(self.unused_addr_groups)}, Svc: {len(self.unused_services)}, SvcGrp: {len(self.unused_svc_groups)}")
        # print(f"DEBUG Unused - Intf: {len(self.unused_interfaces)}, Zone: {len(self.unused_zones)}, VIP: {len(self.unused_vips)}, Pool: {len(self.unused_ippools)}, Route: {len(self.unused_routes)}, VPN P1: {len(self.unused_phase1)}") 

    # --- Reporting Methods --- 

    def generate_unused_report(self, output_file):
        """Generates a text file listing potentially unused objects."""
        report_file = f"{output_file}_unused_report.txt"
        print(f"Generating unused objects report: {report_file}")
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("--- Potentially Unused Configuration Objects ---\n")
                f.write("Note: Usage analysis is based on enabled firewall policies, static routes referencing used interfaces,\
")
                f.write("      VPN tunnels referenced by policies, VIPs/NAT pools used in policies, and recursive group membership.\n")
                f.write("      Built-in objects (like 'all', 'http') and certain virtual interfaces (like 'ssl.root') are excluded.\n")
                f.write("      This report is a *guide*. Verify usage in dynamic routing, disabled policies, GUI settings, etc. before deleting.\n\n")
                
                sections = {
                    "Address Objects": self.unused_addresses,
                    "Address Groups": self.unused_addr_groups,
                    "Service Objects": self.unused_services,
                    "Service Groups": self.unused_svc_groups,
                    "Interfaces": self.unused_interfaces,
                    "Zones": self.unused_zones,
                    "Virtual IPs (VIPs)": self.unused_vips,
                    "IP Pools": self.unused_ippools,
                    "Static Routes": self.unused_routes,
                    "VPN Phase 1 Tunnels": self.unused_phase1,
                    "VPN Phase 2 Selectors": self.unused_phase2,
                }
                
                total_unused = 0
                for section_title, items in sections.items():
                    sorted_items = sorted(list(items))
                    if sorted_items:
                        f.write(f"--- {section_title} ({len(sorted_items)}) ---\n")
                        total_unused += len(sorted_items)
                        for item in sorted_items:
                            f.write(f"- {item}\n")
                        f.write("\n")
                
                if total_unused == 0:
                     f.write("No potentially unused objects identified based on current analysis scope.\n")
                else:
                     f.write(f"Total potentially unused objects found: {total_unused}\n")
                     
            print(f"Successfully wrote unused report to {report_file}")
        except OSError as e:
            print(f"Error writing unused report file {report_file}: {e}", file=sys.stderr)

    def generate_relationship_summary(self):
        """Generates a text summary of key configuration relationships."""
        summary = ["--- Configuration Relationship Summary ---"]

        # Object Counts (Based on initial parse)
        summary.append("\n--- Object Counts (Parsed) ---")
        counts = {
            "Static Routes": len(self.model.routes),
            "Address Objects": len(self.model.addresses),
            "Address Groups": len(self.model.addr_groups),
            "Service Objects": len(self.model.services),
            "Service Groups": len(self.model.svc_groups),
            "Interfaces": len(self.model.interfaces),
            "Zones": len(self.model.zones),
            "Firewall Policies": len(self.model.policies),
            "Virtual IPs (VIPs)": len(self.model.vips),
            "IP Pools": len(self.model.ippools),
            "DHCP Servers": len(self.model.dhcp_servers),
            "VPN Phase1": len(self.model.phase1),
            "VPN Phase2": len(self.model.phase2),
            "SD-WAN Members": len(self.model.sd_wan.get('members', [])),
            "SD-WAN Rules": len(self.model.sd_wan.get('service', [])),
            # Add more counts as needed
        }
        for name, count in counts.items():
             if count > 0:
                  summary.append(f"- {name}: {count}")

        # Usage Counts (Based on analysis)
        summary.append("\n--- Object Counts (Used & Drawn) ---")
        drawn_policy_count = sum(1 for node in self.processed_nodes if node.startswith('pol_'))
        used_counts = {
            "Enabled & Referenced Policies": drawn_policy_count,
            "Interfaces": len(self.used_interfaces),
            "Zones": len(self.used_zones),
            "Address Objects": len(self.used_addresses),
            "Address Groups": len(self.used_addr_groups),
            "Service Objects": len(self.used_services),
            "Service Groups": len(self.used_svc_groups),
            "Virtual IPs (VIPs)": len(self.used_vips),
            "IP Pools": len(self.used_ippools),
            "Static Routes (on used IFs)": len(self.used_routes),
            "VPN Phase1 Tunnels": len(self.used_phase1),
            "VPN Phase2 Selectors": len(self.used_phase2),
        }
        for name, count in used_counts.items():
            summary.append(f"- {name}: {count}")
            
        # Grouping Complexity
        summary.append("\n--- Grouping Complexity ---")
        addr_depths = self.relationship_stats.get('address_group_depth', {})
        svc_depths = self.relationship_stats.get('service_group_depth', {})
        max_addr_depth = max((d for d in addr_depths.values() if isinstance(d, int)), default=0)
        max_svc_depth = max((d for d in svc_depths.values() if isinstance(d, int)), default=0)
        summary.append(f"- Max Address Group Nesting Depth: {max_addr_depth}")
        summary.append(f"- Max Service Group Nesting Depth: {max_svc_depth}")
        addr_cycles = [name for name, depth in addr_depths.items() if depth == 'Cycle Detected']
        svc_cycles = [name for name, depth in svc_depths.items() if depth == 'Cycle Detected']
        if addr_cycles:
            summary.append(f"- WARNING: Cycle detected involving Address Group(s): {', '.join(addr_cycles)}")
        if svc_cycles:
            summary.append(f"- WARNING: Cycle detected involving Service Group(s): {', '.join(svc_cycles)}")
            
        # High Usage Objects (Top 5)
        summary.append("\n--- High Usage Objects (Referenced by most policies) ---")
        top_n = 5
        # Interfaces/Zones/Tunnels
        endpoint_counts = sorted(self.relationship_stats.get('interface_policy_count', {}).items(), key=lambda item: item[1], reverse=True)
        summary.append(f"  Interfaces/Zones/Tunnels:")
        for item, count in endpoint_counts[:top_n]: summary.append(f"    - {item}: {count} policies")
        if not endpoint_counts: summary.append("    (None)")
        # Addresses/Groups/VIPs
        addr_counts = sorted(self.relationship_stats.get('address_policy_count', {}).items(), key=lambda item: item[1], reverse=True)
        summary.append(f"  Addresses/Groups/VIPs:")
        for item, count in addr_counts[:top_n]: summary.append(f"    - {item}: {count} policies")
        if not addr_counts: summary.append("    (None)")
        # Services/Groups
        svc_counts = sorted(self.relationship_stats.get('service_policy_count', {}).items(), key=lambda item: item[1], reverse=True)
        summary.append(f"  Services/Groups:")
        for item, count in svc_counts[:top_n]: summary.append(f"    - {item}: {count} policies")
        if not svc_counts: summary.append("    (None)")

        # Unused Objects Summary
        summary.append("\n--- Potentially Unused Objects Summary ---")
        unused_counts_summary = {
            "Address Objects": len(self.unused_addresses),
            "Address Groups": len(self.unused_addr_groups),
            "Service Objects": len(self.unused_services),
            "Service Groups": len(self.unused_svc_groups),
            "Interfaces": len(self.unused_interfaces),
            "Zones": len(self.unused_zones),
            "VIPs": len(self.unused_vips),
            "IP Pools": len(self.unused_ippools),
            "Static Routes": len(self.unused_routes),
            "VPN Tunnels (P1)": len(self.unused_phase1),
            "VPN Selectors (P2)": len(self.unused_phase2),
        }
        has_unused = False
        for name, count in unused_counts_summary.items():
             if count > 0:
                  summary.append(f"- {name}: {count}")
                  has_unused = True
        if not has_unused:
             summary.append("(No potentially unused objects identified)")
        else:
            summary.append("(See separate unused report file for details)")

        return "\n".join(summary)

    def generate_diagram(self, output_file='network_topology'):
        """Generates the final network diagram focusing on used objects and relationships."""
        print("Generating network diagram...")
        # 1. Analyze relationships to identify used objects (must be done first)
        self.analyze_relationships()

        # 2. Generate nodes and clusters based on the analysis
        # Order matters for visual grouping and dependencies.
        # Basic network structure first:
        self.generate_network_hierarchy() # Includes Zones, Interfaces, connected Networks, Routes
        
        # Security elements:
        self.generate_policies() # Includes Addr/Svc object nodes, Policy nodes, and connects them
        
        # NAT elements:
        self.generate_nat_configuration() # Includes VIP/Pool nodes and connects policies
        
        # Other features:
        self.generate_sd_wan() # Includes SD-WAN cluster, members, rules
        self.generate_vpn_tunnels() # Includes VPN cluster, P1, P2 nodes
        
        # 3. Render the diagram
        output_path = output_file
        print(f"Attempting to render diagram to {output_path}.[png|svg]...")
        try:
            # Render PNG
            png_filename = self.graph.render(output_path, format='png', view=False, cleanup=True)
            print(f"Successfully generated PNG diagram: {png_filename}")
            # Render SVG
            svg_filename = self.graph.render(output_path, format='svg', view=False, cleanup=True)
            print(f"Successfully generated SVG diagram: {svg_filename}")
        except Exception as e:
            print(f"\nError rendering graph with Graphviz: {e}", file=sys.stderr)
            print("Ensure Graphviz executables (dot) are installed and in your system's PATH.", file=sys.stderr)
            # Attempt to save the DOT source file anyway for manual rendering
            try:
                 dot_filename = f"{output_path}.gv"
                 self.graph.save(filename=dot_filename)
                 print(f"Saved DOT source file for manual inspection/rendering: {dot_filename}")
            except Exception as dot_e:
                 print(f"Error saving DOT source file: {dot_e}", file=sys.stderr)

        # 4. Generate the unused objects report
        self.generate_unused_report(output_file)
        
        # 5. Generate and print the relationship summary
        summary = self.generate_relationship_summary()
        print("\n" + summary)
        # Optionally save summary to file
        summary_file = f"{output_file}_summary.txt"
        try:
             with open(summary_file, 'w', encoding='utf-8') as f:
                  f.write(summary)
             print(f"Successfully saved relationship summary to {summary_file}")
        except OSError as e:
             print(f"Error writing summary file {summary_file}: {e}", file=sys.stderr)


    # --- Path Tracing Logic --- 

    def _ip_in_subnet(self, ip_str, subnet_str):
        """Check if an IP address string is within a subnet string."""
        try:
            ip = ipaddress.ip_address(ip_str)
            subnet = ipaddress.ip_network(subnet_str, strict=False)
            return ip in subnet
        except ValueError:
            # Handle cases where subnet_str might be FQDN or invalid
            return False

    def _resolve_address_object(self, name, visited=None):
        """Recursively resolve an address object/group name to a list of network objects.
           Returns list containing ipaddress.ip_network, ipaddress.ip_address, or str (for FQDN).
           Handles cycles.
        """
        if visited is None: visited = set()
        if name in visited: 
            # print(f"DEBUG: Cycle detected resolving address object: {name}")
            return [] # Cycle detected
        visited.add(name)
        
        resolved = []
        if name in self.model.addresses:
            addr_data = self.model.addresses[name]
            addr_type = addr_data.get('type')
            subnet_val = addr_data.get('subnet')
            if not subnet_val: 
                 visited.remove(name)
                 return []

            if addr_type == 'ipmask':
                try:
                    resolved.append(ipaddress.ip_network(subnet_val, strict=False))
                except ValueError:
                     print(f"Warning: Invalid IP/subnet '{subnet_val}' in address object '{name}'", file=sys.stderr)
            elif addr_type == 'iprange':
                 # Convert range to individual IPs or networks if possible (can be large!)
                 # Simplification for trace: treat range start as representative? Or return range tuple?
                 # For now, just try to parse start/end as IPs
                 try:
                     start_ip_str, end_ip_str = subnet_val.split('-')
                     start_ip = ipaddress.ip_address(start_ip_str.strip())
                     end_ip = ipaddress.ip_address(end_ip_str.strip())
                     # Return start/end tuple to represent range for policy check?
                     # For routing check, maybe just the start IP?
                     resolved.append((start_ip, end_ip)) # Represent range as tuple for policy check
                 except ValueError:
                     print(f"Warning: Invalid IP range format '{subnet_val}' in address object '{name}'", file=sys.stderr)
            elif addr_type == 'fqdn':
                 resolved.append(subnet_val) # Keep FQDN as string
            elif addr_type == 'wildcard': # Very difficult to resolve for path tracing
                 print(f"Warning: Wildcard address object '{name}' ({subnet_val}) not supported for path tracing.", file=sys.stderr)
            # TODO: Add other types like geography, dynamic etc. if needed
            
        elif name in self.model.addr_groups:
            for member in self.model.addr_groups[name]:
                resolved.extend(self._resolve_address_object(member, visited.copy()))
        else:
             # Maybe it's a direct IP or subnet string? Try parsing.
             try:
                  resolved.append(ipaddress.ip_network(name, strict=False))
             except ValueError:
                  # Not an address object, group, or valid IP/subnet string
                  # Could be an FQDN implicitly, or just not found. 
                  # Let policy check handle FQDNs if necessary.
                  # print(f"Debug: Address '{name}' not found in objects/groups and not valid IP/subnet.")
                  pass 
        
        visited.remove(name) # Backtrack
        return resolved
        
    def _resolve_service_object(self, name, visited=None):
        """Recursively resolve a service object/group to a list of (protocol, port_start, port_end) tuples.
           Port range uses start/end, single port has start=end.
           Handles ICMP with port_start=icmp_type, port_end=icmp_code (or None).
           Protocol 'any' covers all. Ports None, None cover all ports.
        """
        if visited is None: visited = set()
        if name in visited: 
            # print(f"DEBUG: Cycle detected resolving service object: {name}")
            return [] # Cycle detection
        visited.add(name)
        
        resolved = []
        # Handle 'ANY' or 'ALL' explicitly
        if name.upper() == 'ALL' or name.upper() == 'ANY':
             resolved.append(('any', None, None))
             visited.remove(name)
             return resolved
             
        if name in self.model.services:
            svc_data = self.model.services[name]
            protocol_str = svc_data.get('protocol', 'TCP/UDP/SCTP').lower() # Default if missing
            port_range = svc_data.get('port') # Can be single, range, multiple, absent
            
            # Determine protocol(s)
            protocols_to_add = set()
            if protocol_str == 'tcp/udp/sctp':
                protocols_to_add.update(['tcp', 'udp', 'sctp'])
            elif protocol_str == 'ip': # Protocol number 0 usually means any IP protocol
                protocols_to_add.add('any') # Represent any IP protocol
            elif protocol_str in ['icmp', 'icmp6']:
                 protocols_to_add.add(protocol_str)
            else: # Assume it's tcp, udp, sctp, or a specific protocol name/number
                 protocols_to_add.add(protocol_str)
                 
            # Parse port(s) / ICMP types
            ports_or_types = []
            if protocol_str in ['icmp', 'icmp6']:
                 icmp_type = svc_data.get('icmptype')
                 icmp_code = svc_data.get('icmpcode')
                 try: p_start = int(icmp_type) if icmp_type is not None else None
                 except ValueError: p_start = None
                 try: p_end = int(icmp_code) if icmp_code is not None else None
                 except ValueError: p_end = None
                 ports_or_types.append((p_start, p_end))
            elif port_range: # Parse TCP/UDP/SCTP ports
                for p_part in port_range.split():
                    if '-' in p_part:
                        try:
                            start, end = map(int, p_part.split('-', 1))
                            ports_or_types.append((start, end))
                        except ValueError:
                            print(f"Warning: Invalid port range '{p_part}' in service '{name}'", file=sys.stderr)
                    else:
                        try:
                            port_num = int(p_part)
                            ports_or_types.append((port_num, port_num))
                        except ValueError:
                             print(f"Warning: Invalid port number '{p_part}' in service '{name}'", file=sys.stderr)
            else: # No port specified (e.g., for IP protocol or any port)
                 ports_or_types.append((None, None))

            # Combine protocols and ports/types
            for proto in protocols_to_add:
                 for p_start, p_end in ports_or_types:
                      resolved.append((proto, p_start, p_end))

        elif name in self.model.svc_groups:
            for member in self.model.svc_groups[name]:
                resolved.extend(self._resolve_service_object(member, visited.copy()))
        # else: Service name not found in custom services or groups (could be built-in?)
        # We don't explicitly handle built-ins here, assume policy check might know them.

        visited.remove(name) # Backtrack
        # Remove duplicates (e.g., if 'tcp/80' is added multiple times via groups)
        return list(set(resolved)) 

    def _find_source_interface(self, source_ip_str):
        """Find the FortiGate interface the source IP likely belongs to.
           Returns (interface_name, message) or (None, error_message).
        """
        try:
            source_ip = ipaddress.ip_address(source_ip_str)
        except ValueError:
            return None, f"Invalid source IP format: {source_ip_str}"
        
        best_match_intf = None
        longest_prefix = -1

        for intf_name, intf_data in self.model.interfaces.items():
            # Check primary IP
            if 'ip' in intf_data and '/' in intf_data['ip']:
                try:
                    iface_network = ipaddress.ip_network(intf_data['ip'], strict=False)
                    if source_ip in iface_network:
                        if iface_network.prefixlen > longest_prefix:
                            longest_prefix = iface_network.prefixlen
                            best_match_intf = intf_name
                except ValueError:
                    continue # Ignore interfaces with invalid primary IP/mask
            
            # Check secondary IPs (if parsed and stored as a list)
            # Assuming secondary IPs are stored in a list under 'secondary_ip' key
            secondary_ips = intf_data.get('secondary_ip', [])
            if isinstance(secondary_ips, list):
                for sec_ip_data in secondary_ips:
                     sec_ip_str = sec_ip_data.get('ip') # Assuming format {'ip': '1.1.1.1/24', ...}
                     if sec_ip_str and '/' in sec_ip_str:
                         try:
                             sec_network = ipaddress.ip_network(sec_ip_str, strict=False)
                             if source_ip in sec_network:
                                 if sec_network.prefixlen > longest_prefix:
                                     longest_prefix = sec_network.prefixlen
                                     best_match_intf = intf_name
                         except ValueError:
                             continue # Ignore invalid secondary IP
        
        if best_match_intf:
             intf_ip = self.model.interfaces[best_match_intf].get('ip', '?')
             return best_match_intf, f"Source IP {source_ip_str} matches interface '{best_match_intf}' (subnet: {intf_ip})"
        else:
             return None, f"No directly connected interface found for source IP {source_ip_str}"

    def _find_matching_route(self, dest_ip_str, current_interface=None):
        """Find the best matching route (static or connected) for a destination IP.
           Considers longest prefix match and administrative distance.
           Returns (route_dict | 'connected', outgoing_interface_name, message).
           Returns (None, None, error_message) on failure.
        """
        try:
            dest_ip = ipaddress.ip_address(dest_ip_str)
        except ValueError:
            return None, None, f"Invalid destination IP format: {dest_ip_str}"
            
        best_match_route_info = None # Will store (route_type, route_data, prefixlen, distance)
        longest_prefix = -1
        lowest_distance = 256 # Higher than any valid distance
        
        # --- Check Static Routes --- 
        for route in self.model.routes:
            if route.get('status') == 'disable': continue
            dst_subnet_str = route.get('dst')
            if not dst_subnet_str: continue
            
            try:
                route_network = ipaddress.ip_network(dst_subnet_str, strict=False)
                if dest_ip in route_network:
                    prefixlen = route_network.prefixlen
                    distance = int(route.get('distance', 10)) # Default static distance
                    
                    # Compare with current best match
                    if prefixlen > longest_prefix:
                        # More specific prefix wins
                        longest_prefix = prefixlen
                        lowest_distance = distance
                        best_match_route_info = ('static', route, prefixlen, distance)
                    elif prefixlen == longest_prefix and distance < lowest_distance:
                        # Same prefix, lower distance wins
                        lowest_distance = distance
                        best_match_route_info = ('static', route, prefixlen, distance)
            except ValueError:
                 # Destination might be an interface service or invalid
                 continue 
                 
        # --- Check Connected Routes --- 
        # Connected routes have distance 0
        connected_distance = 0
        for intf_name, intf_data in self.model.interfaces.items():
            # Check primary IP
            if 'ip' in intf_data and '/' in intf_data['ip']:
                try:
                    iface_network = ipaddress.ip_network(intf_data['ip'], strict=False)
                    if dest_ip in iface_network:
                        prefixlen = iface_network.prefixlen
                        # Compare with current best match (static or previous connected)
                        if prefixlen > longest_prefix:
                             longest_prefix = prefixlen
                             lowest_distance = connected_distance
                             # Store interface info instead of route dict
                             best_match_route_info = ('connected', {'device': intf_name, 'dst': str(iface_network)}, prefixlen, connected_distance)
                        elif prefixlen == longest_prefix and connected_distance < lowest_distance:
                             lowest_distance = connected_distance
                             best_match_route_info = ('connected', {'device': intf_name, 'dst': str(iface_network)}, prefixlen, connected_distance)
                except ValueError:
                     continue
            # Check secondary IPs
            secondary_ips = intf_data.get('secondary_ip', [])
            if isinstance(secondary_ips, list):
                for sec_ip_data in secondary_ips:
                     sec_ip_str = sec_ip_data.get('ip')
                     if sec_ip_str and '/' in sec_ip_str:
                         try:
                             sec_network = ipaddress.ip_network(sec_ip_str, strict=False)
                             if dest_ip in sec_network:
                                 prefixlen = sec_network.prefixlen
                                 if prefixlen > longest_prefix:
                                     longest_prefix = prefixlen
                                     lowest_distance = connected_distance
                                     best_match_route_info = ('connected', {'device': intf_name, 'dst': str(sec_network)}, prefixlen, connected_distance)
                                 elif prefixlen == longest_prefix and connected_distance < lowest_distance:
                                     lowest_distance = connected_distance
                                     best_match_route_info = ('connected', {'device': intf_name, 'dst': str(sec_network)}, prefixlen, connected_distance)
                         except ValueError:
                              continue
                              
        # --- Process Best Match --- 
        if best_match_route_info:
            route_type, route_data, prefixlen, distance = best_match_route_info
            outgoing_interface = route_data.get('device')
            
            if not outgoing_interface:
                 return None, None, f"Routing error: Best match route ({route_data.get('dst')}) has no outgoing device specified."

            # Construct message
            if route_type == 'static':
                 gw = route_data.get('gateway', 'connected')
                 msg = f"Found matching static route: {route_data.get('dst')} via {gw} on interface '{outgoing_interface}' (Prefix: {prefixlen}, Dist: {distance})"
                 final_route_data = route_data
            else: # connected
                 msg = f"Destination {dest_ip_str} is directly connected to interface '{outgoing_interface}' (Network: {route_data.get('dst')}, Prefix: {prefixlen}, Dist: {distance})"
                 final_route_data = 'connected' # Use special marker for connected routes
            
            # Check for potential hairpinning (route points back to ingress interface)
            if outgoing_interface == current_interface:
                 print(f"Trace Info: Route for {dest_ip_str} points back to the current interface '{current_interface}'. This might indicate hairpinning or a loop.", file=sys.stderr)
            
            return final_route_data, outgoing_interface, msg
        else:
            # Check for default route (0.0.0.0/0) among static routes if no specific match
            for route in self.model.routes:
                 if route.get('status') != 'disable' and route.get('dst') == '0.0.0.0/0.0.0.0':
                     outgoing_interface = route.get('device')
                     if outgoing_interface:
                         gw = route.get('gateway', 'connected')
                         distance = int(route.get('distance', 10))
                         msg = f"Using default route: {route.get('dst')} via {gw} on interface '{outgoing_interface}' (Dist: {distance})"
                         return route, outgoing_interface, msg
                     else:
                         return None, None, f"Routing error: Default route found but has no outgoing device specified."

            # No route found at all
            return None, None, f"No matching route (static, connected, or default) found for destination {dest_ip_str}"

    def _check_firewall_policy(self, src_ip_str, dst_ip_str, dst_port_str, protocol_str, src_intf_name, dst_intf_name):
        """Check firewall policies for a match based on the 6-tuple.
           Returns the matching policy dictionary and message, or None and message.
           Handles interface/zone matching, address/group resolution, service resolution.
        """
        if not src_intf_name or not dst_intf_name:
            return None, "Policy check failed: Missing source or destination interface."

        # --- Prepare Check Inputs --- 
        try:
             check_src_ip = ipaddress.ip_address(src_ip_str)
             check_dst_ip = ipaddress.ip_address(dst_ip_str)
        except ValueError as e:
             return None, f"Policy check failed: Invalid IP address - {e}"
             
        check_proto = protocol_str.lower()
        check_port = None
        check_icmp_type = None
        check_icmp_code = None
        
        if check_proto in ['tcp', 'udp', 'sctp']:
             try:
                 check_port = int(dst_port_str)
             except (ValueError, TypeError):
                 return None, f"Policy check failed: Invalid destination port '{dst_port_str}' for protocol {check_proto}"
        elif check_proto in ['icmp', 'icmp6']:
             # If tracing ICMP, dst_port_str might represent type/code
             # Example: dst_port_str="8:0" for echo request
             # For simplicity now, we don't parse type/code from input, just check protocol match.
             pass # ICMP check is primarily protocol-based for now
        # else: Other protocols (e.g., ip, gre) - no port check needed

        # Resolve source/destination interfaces to zones if they belong to one
        src_zone = next((z_name for z_name, z_data in self.model.zones.items() if src_intf_name in z_data.get('interface', [])), None)
        dst_zone = next((z_name for z_name, z_data in self.model.zones.items() if dst_intf_name in z_data.get('interface', [])), None)
        
        src_match_candidates = {src_intf_name, src_zone} if src_zone else {src_intf_name}
        dst_match_candidates = {dst_intf_name, dst_zone} if dst_zone else {dst_intf_name}
        
        # print(f"DEBUG Policy Check: Src Intf/Zone Candidates: {src_match_candidates}")
        # print(f"DEBUG Policy Check: Dst Intf/Zone Candidates: {dst_match_candidates}")
        # print(f"DEBUG Policy Check: Src IP: {check_src_ip}, Dst IP: {check_dst_ip}, Dst Port: {check_port}, Proto: {check_proto}")

        # --- Iterate Through Policies (Order Matters!) ---
        for policy in self.model.policies:
            policy_id = policy.get('id', 'N/A')
            if policy.get('status') == 'disable': continue
            # print(f"DEBUG Policy Check: Evaluating Policy ID {policy_id}...")
            
            # 1. Match Source Interface/Zone
            policy_srcintf = set(policy.get('srcintf', []))
            if not policy_srcintf.intersection(src_match_candidates):
                 # print(f"DEBUG Policy Check: Policy {policy_id} - Fail Src Intf ({policy_srcintf})")
                 continue

            # 2. Match Destination Interface/Zone
            policy_dstintf = set(policy.get('dstintf', []))
            if not policy_dstintf.intersection(dst_match_candidates):
                 # print(f"DEBUG Policy Check: Policy {policy_id} - Fail Dst Intf ({policy_dstintf})")
                 continue
                 
            # 3. Match Source Address
            srcaddr_match = self._check_address_match(policy.get('srcaddr', []), check_src_ip)
            if not srcaddr_match:
                 # print(f"DEBUG Policy Check: Policy {policy_id} - Fail Src Addr ({policy.get('srcaddr', [])})")
                 continue
                 
            # 4. Match Destination Address (handles VIPs implicitly via resolution)
            dstaddr_match = self._check_address_match(policy.get('dstaddr', []), check_dst_ip)
            if not dstaddr_match:
                 # print(f"DEBUG Policy Check: Policy {policy_id} - Fail Dst Addr ({policy.get('dstaddr', [])})")
                 continue
                 
            # 5. Match Service (Protocol and Port/Type/Code)
            service_match = self._check_service_match(policy.get('service', []), check_proto, check_port, check_icmp_type, check_icmp_code)
            if not service_match:
                 # print(f"DEBUG Policy Check: Policy {policy_id} - Fail Service ({policy.get('service', [])})")
                 continue
                 
            # --- Match Found --- 
            # print(f"DEBUG Policy Check: Policy ID {policy_id} is a match.")
            action = policy.get('action', 'deny').lower()
            msg = f"Matched Policy ID {policy_id} (Action: {action})"
            # Append NAT info if relevant
            if policy.get('nat') == 'enable':
                if policy.get('ippool') == 'enable':
                     msg += f" - NAT enabled (Pool: {policy.get('poolname', 'N/A')})"
                else:
                     msg += f" - NAT enabled (Outgoing Interface IP)"
            # Append Security Profiles info if present
            sec_profiles = []
            for profile_key in ['av_profile', 'webfilter_profile', 'ips_sensor', 'application_list', 'ssl_ssh_profile']:
                profile_name = policy.get(profile_key)
                if profile_name and profile_name != '-': # Assuming '-' or missing means disabled
                     sec_profiles.append(f"{profile_key.split('_')[0].upper()}:{profile_name}")
            if sec_profiles:
                 msg += f" - Sec Profiles: [{', '.join(sec_profiles)}]"
                     
            return policy, msg

        # --- No Match Found --- 
        return None, "No matching firewall policy found (Implicit Deny)"

    def _check_address_match(self, policy_addrs, check_ip):
        """Check if check_ip matches any resolved address in policy_addrs."""
        if not policy_addrs: return False # Or True if empty means 'all'? Assume False.
        
        for addr_name in policy_addrs:
            if addr_name.lower() in ['all', 'any']:
                return True
            resolved_items = self._resolve_address_object(addr_name)
            for item in resolved_items:
                 if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                     if check_ip in item:
                         return True
                 elif isinstance(item, tuple) and len(item) == 2: # IP Range (start_ip, end_ip)
                      start_ip, end_ip = item
                      if start_ip <= check_ip <= end_ip:
                           return True
                 elif isinstance(item, str): # FQDN - cannot resolve/match in trace
                      # print(f"Debug Addr Check: Skipping FQDN '{item}'")
                      pass 
        return False

    def _check_service_match(self, policy_svcs, check_proto, check_port, check_icmp_type, check_icmp_code):
        """Check if the protocol/port/type/code matches any resolved service in policy_svcs."""
        if not policy_svcs: return False # Or True if empty means 'ALL'? Assume False.
        
        for svc_name in policy_svcs:
            if svc_name.upper() in ['ALL', 'ANY']:
                return True
            resolved_tuples = self._resolve_service_object(svc_name)
            for r_proto, r_port_start, r_port_end in resolved_tuples:
                # Protocol check
                proto_match = False
                if r_proto == 'any' or r_proto == check_proto:
                    proto_match = True
                elif check_proto in ['tcp','udp','sctp'] and r_proto == 'tcp/udp/sctp':
                     proto_match = True # Service covers multiple, including the check proto
                
                if not proto_match: continue
                    
                # Port / ICMP Type/Code check
                port_type_match = False
                if r_proto in ['icmp', 'icmp6']:
                     # Policy uses ICMP type/code (r_port_start=type, r_port_end=code)
                     # We currently don't parse check_icmp_type/code from input, so assume match if protocol matches.
                     # TODO: Enhance trace input to include ICMP type/code for stricter check
                     policy_type = r_port_start
                     policy_code = r_port_end
                     if policy_type is None: # Policy allows any type
                         port_type_match = True
                     elif check_icmp_type == policy_type:
                          if policy_code is None or check_icmp_code == policy_code: # Match type, and code if specified
                              port_type_match = True
                     # For now, simplify: If protocol matches, assume match.
                     port_type_match = True 
                elif check_port is not None: # TCP/UDP/SCTP
                     if r_port_start is None and r_port_end is None:
                          port_type_match = True # Policy service allows any port
                     elif r_port_start is not None and r_port_end is not None:
                          if r_port_start <= check_port <= r_port_end:
                               port_type_match = True
                     # else: Malformed port data from resolver?
                else: # Protocol doesn't use ports (e.g., IP, GRE)
                     port_type_match = True 
                     
                if proto_match and port_type_match:
                    return True # Found a match
                    
        return False # No match found in any policy service

    def _apply_nat(self, policy, original_src_ip_str, original_dst_ip_str, original_dst_port_str, protocol_str):
        """Calculate the effects of NAT based on the matched policy.
           Returns (new_src_ip, new_dst_ip, new_dst_port, nat_description_str).
           Returns original values and "No NAT" if no NAT applies.
        """
        nat_desc = "No NAT"
        new_src_ip = original_src_ip_str
        new_dst_ip = original_dst_ip_str
        new_dst_port = original_dst_port_str
        protocol = protocol_str.lower()

        # --- Source NAT (SNAT) --- 
        if policy.get('nat') == 'enable':
            snat_applied = False
            if policy.get('ippool') == 'enable' and 'poolname' in policy:
                pool_name = policy['poolname']
                if pool_name in self.model.ippools:
                    pool_data = self.model.ippools[pool_name]
                    pool_type = pool_data.get('type')
                    start_ip = pool_data.get('startip')
                    # Simplification: Use the start IP of the pool for the trace
                    if start_ip:
                         new_src_ip = start_ip
                         nat_desc = f"SNAT(Pool:'{pool_name}' Type:{pool_type}): {original_src_ip_str} -> {new_src_ip}"
                         snat_applied = True
                    else:
                         nat_desc = f"SNAT(Pool:'{pool_name}'): Error - Pool details missing StartIP"
                else:
                    nat_desc = f"SNAT Error: Configured with Pool '{pool_name}', but pool not found."
            else:
                 # NAT using outgoing interface IP
                 dst_intf_name = policy.get('dstintf', [None])[0] # Assume first egress interface
                 if dst_intf_name and dst_intf_name in self.model.interfaces:
                     out_intf_ip_cidr = self.model.interfaces[dst_intf_name].get('ip')
                     if out_intf_ip_cidr and '/' in out_intf_ip_cidr:
                          try:
                             intf_ip_obj = ipaddress.ip_interface(out_intf_ip_cidr).ip
                             new_src_ip = str(intf_ip_obj)
                             nat_desc = f"SNAT(Interface:{dst_intf_name}): {original_src_ip_str} -> {new_src_ip}"
                             snat_applied = True
                          except ValueError:
                             nat_desc = f"SNAT Error: Outgoing Interface '{dst_intf_name}' IP format invalid ({out_intf_ip_cidr})."
                     else:
                         nat_desc = f"SNAT Error: Outgoing Interface '{dst_intf_name}' has no IP address configured."
                 else:
                      nat_desc = f"SNAT Error: Outgoing Interface not found or not specified in policy."
            
            # Clear nat_desc if SNAT wasn't actually applied successfully
            if not snat_applied:
                 nat_desc = "SNAT Error (see log)" # Keep original src IP
                 new_src_ip = original_src_ip_str
        
        # --- Destination NAT (DNAT via VIP) --- 
        # Check if the *original* destination IP matched a VIP specified in the policy's dstaddr
        matched_vip_name = None
        vip_data = None
        try:
             check_dst_ip_obj = ipaddress.ip_address(original_dst_ip_str)
        except ValueError:
             check_dst_ip_obj = None # Cannot check VIP if original dest IP is invalid
             
        if check_dst_ip_obj:
             for addr_name in policy.get('dstaddr', []):
                 if addr_name in self.model.vips:
                     current_vip_data = self.model.vips[addr_name]
                     vip_extip_str = current_vip_data.get('extip')
                     if vip_extip_str:
                         # Check if original destination IP falls within VIP external IP range/subnet
                         try:
                             # Handle single IP, range, or subnet in extip
                             if '-' in vip_extip_str: # Range
                                 start, end = vip_extip_str.split('-')
                                 if ipaddress.ip_address(start.strip()) <= check_dst_ip_obj <= ipaddress.ip_address(end.strip()):
                                      matched_vip_name = addr_name
                                      vip_data = current_vip_data
                                      break
                             else: # Single IP or Subnet
                                 vip_ext_net = ipaddress.ip_network(vip_extip_str, strict=False)
                                 if check_dst_ip_obj in vip_ext_net:
                                      matched_vip_name = addr_name
                                      vip_data = current_vip_data
                                      break
                         except ValueError:
                             print(f"Warning: Invalid VIP extip format '{vip_extip_str}' for VIP '{addr_name}'", file=sys.stderr)
                             pass # Ignore invalid VIP extip
        
        if matched_vip_name and vip_data:
            dnat_applied = False
            mapped_ip_list = vip_data.get('mappedip', [])
            if mapped_ip_list:
                # Simplification: Use the *first* mapped IP range/address for the trace
                first_map_info = mapped_ip_list[0]
                mapped_ip_str = first_map_info.get('range')
                if mapped_ip_str:
                    try:
                        # Try parsing as network first (most common for single IP map)
                        mapped_net = ipaddress.ip_network(mapped_ip_str, strict=False)
                        # Use the network address if /32, else maybe first usable? Use network address for simplicity.
                        potential_new_dst_ip = str(mapped_net.network_address if mapped_net.prefixlen == 32 else mapped_net.network_address) 
                        # If it's a real range, might need refinement
                        if '-' in mapped_ip_str: # Handle range explicitly? Assume start for now
                             potential_new_dst_ip = str(ipaddress.ip_address(mapped_ip_str.split('-')[0].strip()))
                        
                        new_dst_ip = potential_new_dst_ip
                        dnat_desc_part = f"DNAT(VIP:'{matched_vip_name}'): {original_dst_ip_str} -> {new_dst_ip}"
                        dnat_applied = True
                    except ValueError:
                        dnat_desc_part = f"DNAT Error: Invalid mapped IP '{mapped_ip_str}' in VIP '{matched_vip_name}'"
                        new_dst_ip = original_dst_ip_str # Fallback
                         
                    # Port Forwarding Check
                    portfwd_desc_part = ""
                    if vip_data.get('portforward') == 'enable':
                        vip_proto = vip_data.get('protocol', 'any').lower()
                        proto_match = (vip_proto == 'any' or vip_proto == protocol)
                        if proto_match and (protocol in ['tcp', 'udp', 'sctp']): # Port fwd only for these
                             ext_port_str = vip_data.get('extport')
                             map_port_str = vip_data.get('mappedport')
                             if ext_port_str and map_port_str:
                                 try:
                                     # Simplification: Check if original dest port matches start of ext port range
                                     ext_port_start = int(ext_port_str.split('-')[0])
                                     original_dst_port_int = int(original_dst_port_str)
                                     
                                     if original_dst_port_int == ext_port_start: # TODO: Handle ext port range match
                                         # Use start of mapped port range
                                         new_dst_port_int = int(map_port_str.split('-')[0])
                                         new_dst_port = str(new_dst_port_int)
                                         portfwd_desc_part = f", Port {original_dst_port_str} -> {new_dst_port}"
                                 except (ValueError, TypeError):
                                      print(f"Warning: Invalid port format in VIP '{matched_vip_name}' (Ext: {ext_port_str}, Map: {map_port_str})", file=sys.stderr)
                                      portfwd_desc_part = ", Port Fwd Error (Invalid Format)"
                                 except Exception as e: # Catch potential int conversion error if original_dst_port_str is invalid
                                      print(f"Warning: Could not compare ports for VIP '{matched_vip_name}', original port '{original_dst_port_str}' invalid? Error: {e}", file=sys.stderr)
                                      portfwd_desc_part = ", Port Fwd Error (Comparison Failed)"
                                      
                    # Combine NAT descriptions
                    final_dnat_desc = dnat_desc_part + portfwd_desc_part
                    if nat_desc != "No NAT" and dnat_applied:
                         nat_desc += "; " + final_dnat_desc
                    elif dnat_applied:
                         nat_desc = final_dnat_desc
                    elif nat_desc == "No NAT": # DNAT failed, don't overwrite SNAT error
                         nat_desc = final_dnat_desc # Show DNAT error
                    else: # SNAT error exists, append DNAT error
                         nat_desc += "; " + final_dnat_desc
                         
                else: # Mapped IP string was empty
                     dnat_fail_desc = f"DNAT Error: VIP '{matched_vip_name}' has empty mapped IP range."
                     if nat_desc != "No NAT": nat_desc += "; " + dnat_fail_desc
                     else: nat_desc = dnat_fail_desc
                     new_dst_ip = original_dst_ip_str # Fallback
            else:
                 dnat_fail_desc = f"DNAT Error: VIP '{matched_vip_name}' matched but has no mapped IP list."
                 if nat_desc != "No NAT": nat_desc += "; " + dnat_fail_desc
                 else: nat_desc = dnat_fail_desc
                 new_dst_ip = original_dst_ip_str # Fallback

        return new_src_ip, new_dst_ip, new_dst_port, nat_desc

    def trace_network_path(self, source_ip, dest_ip, dest_port, protocol='tcp', max_hops=30):
        """Simulates the path of a packet through the FortiGate configuration.
        
        Args:
            source_ip (str): The source IP address.
            dest_ip (str): The destination IP address.
            dest_port (str): The destination port number (or ICMP type/code like '8:0').
            protocol (str): The protocol (tcp, udp, icmp, etc.).
            max_hops (int): Maximum number of internal hops (route lookups) to simulate.

        Returns:
            tuple: (list of hop dictionaries, status message string)
                   Hop dictionaries contain details about each step (routing, policy, nat).
                   Status message indicates success, failure, or blockage reason.
        """
        path = []
        current_hop_num = 0
        ingress_intf = None
        current_intf = None # Tracks the interface the packet is currently 'on' or arrived at
        
        # Track state across hops
        current_src_ip = source_ip
        current_dst_ip = dest_ip
        current_dst_port = dest_port
        current_proto = protocol
        
        final_status = "Trace initiated."
        print(f"\n--- Starting Path Trace ---")
        print(f"Initial Packet: {current_src_ip} -> {current_dst_ip}:{current_dst_port} (proto: {current_proto})")
        print(f"Max Hops: {max_hops}")
        print("-"*25)

        # --- 1. Find Ingress Interface --- 
        ingress_intf, msg = self._find_source_interface(current_src_ip)
        path.append({'hop': current_hop_num, 'type': 'Ingress Lookup', 'detail': msg, 'interface': ingress_intf})
        if not ingress_intf:
            return path, f"Failed: {msg}"
        current_intf = ingress_intf
        print(f"Hop {current_hop_num}: Ingress - {msg}")

        # --- Simulation Loop (Max hops to prevent infinite loops) ---
        for hop_num in range(1, max_hops + 1):
            current_hop_num = hop_num
            print(f"\nHop {current_hop_num}: State - Ingress='{ingress_intf}', Current='{current_intf}', Dst='{current_dst_ip}'")
            
            # --- 2. Routing Lookup --- 
            # Route lookup is based on the current destination IP
            route_info, egress_intf, route_msg = self._find_matching_route(current_dst_ip, current_intf)
            hop_details = {
                'hop': current_hop_num, 
                'type': 'Routing', 
                'detail': route_msg, 
                'lookup_ip': current_dst_ip,
                'route_type': None, 
                'route_dest': None,
                'route_gw': None,
                'egress_interface': egress_intf
            }
            if isinstance(route_info, dict): # Static or Default route
                hop_details['route_type'] = 'static' if route_info.get('dst') != '0.0.0.0/0.0.0.0' else 'default'
                hop_details['route_dest'] = route_info.get('dst')
                hop_details['route_gw'] = route_info.get('gateway')
            elif route_info == 'connected':
                 hop_details['route_type'] = 'connected'
                 # Find the connected network details if needed (already in msg)
            path.append(hop_details)
            print(f"Hop {current_hop_num}: Routing - {route_msg}")
            
            if not egress_intf:
                 final_status = f"Blocked (Hop {current_hop_num}): No route found. {route_msg}"
                 break # Routing failure
                 
            # --- 3. Firewall Policy Check --- 
            # Policy check uses the current source/dest IPs and the determined ingress/egress interfaces
            policy, policy_msg = self._check_firewall_policy(
                 current_src_ip, current_dst_ip, current_dst_port, 
                 current_proto, current_intf, egress_intf # Use current interface as source IF for policy
            )
            path.append({
                'hop': current_hop_num, 
                'type': 'Policy Check',
                'detail': policy_msg, 
                'policy_id': policy.get('id') if policy else None,
                'policy_action': policy.get('action') if policy else 'implicit_deny',
                'src_intf_zone': f"{current_intf} / {src_zone}" if (src_zone := next((z for z, d in self.model.zones.items() if current_intf in d.get('interface', [])), None)) else current_intf,
                'dst_intf_zone': f"{egress_intf} / {dst_zone}" if (dst_zone := next((z for z, d in self.model.zones.items() if egress_intf in d.get('interface', [])), None)) else egress_intf,
            })
            print(f"Hop {current_hop_num}: Policy Check - {policy_msg}")
            
            if not policy or policy.get('action', 'deny').lower() != 'accept':
                 final_status = f"Blocked (Hop {current_hop_num}): {policy_msg}"
                 break # Denied by policy

            # --- 4. Apply NAT --- 
            nat_src_ip, nat_dst_ip, nat_dst_port, nat_msg = self._apply_nat(
                 policy, current_src_ip, current_dst_ip, current_dst_port, current_proto
            )
            path.append({
                'hop': current_hop_num, 
                'type': 'NAT', 
                'detail': nat_msg,
                'pre_nat_src': current_src_ip,
                'post_nat_src': nat_src_ip,
                'pre_nat_dst': current_dst_ip,
                'post_nat_dst': nat_dst_ip, 
                'pre_nat_port': current_dst_port,
                'post_nat_port': nat_dst_port
            })
            print(f"Hop {current_hop_num}: NAT - {nat_msg}")
            
            # Update current packet state *after* NAT for next hop / final egress check
            current_src_ip = nat_src_ip
            current_dst_ip = nat_dst_ip
            current_dst_port = nat_dst_port
            
            # --- 5. Egress / Destination Check --- 
            # Packet is allowed by policy and NAT is applied. Where does it go?
            # Check if the *egress interface* is directly connected to the *current destination IP*
            final_dest_reached = False
            is_connected_on_egress = False
            if egress_intf in self.model.interfaces:
                 intf_data = self.model.interfaces[egress_intf]
                 # Check primary IP subnet
                 if 'ip' in intf_data and '/' in intf_data['ip']:
                     try:
                         egress_net = ipaddress.ip_network(intf_data['ip'], strict=False)
                         if ipaddress.ip_address(current_dst_ip) in egress_net:
                             is_connected_on_egress = True
                     except ValueError:
                         pass 
                 # Check secondary IPs
                 secondary_ips = intf_data.get('secondary_ip', [])
                 if not is_connected_on_egress and isinstance(secondary_ips, list):
                      for sec_ip_data in secondary_ips:
                          sec_ip_str = sec_ip_data.get('ip')
                          if sec_ip_str and '/' in sec_ip_str:
                               try:
                                   sec_net = ipaddress.ip_network(sec_ip_str, strict=False)
                                   if ipaddress.ip_address(current_dst_ip) in sec_net:
                                       is_connected_on_egress = True
                                       break
                               except ValueError:
                                    pass
                                    
            if is_connected_on_egress:
                 final_status = f"Success (Hop {current_hop_num}): Destination {current_dst_ip} reached via interface '{egress_intf}'."
                 final_dest_reached = True
                 path.append({'hop': current_hop_num, 'type': 'Egress/Delivered', 'detail': final_status, 'interface': egress_intf})
                 print(f"Hop {current_hop_num}: Egress - {final_status}")
                 break # Trace successful
            else:
                 # Destination not directly connected to egress IF. Packet is forwarded out.
                 # If the route had a gateway IP, that's the next hop. Otherwise, it's sent towards the destination IP.
                 next_hop_info = f"towards {current_dst_ip}"
                 if isinstance(route_info, dict) and route_info.get('gateway'):
                      next_hop_info = f"via gateway {route_info['gateway']}"
                      
                 final_status = f"Allowed (Hop {current_hop_num}): Packet egresses interface '{egress_intf}' {next_hop_info}."
                 path.append({'hop': current_hop_num, 'type': 'Egress/Forwarded', 'detail': final_status, 'interface': egress_intf})
                 print(f"Hop {current_hop_num}: Egress - {final_status}")
                 # For this simulation, we stop here assuming it left the FortiGate.
                 # To trace internal routing (hairpin, VDOM links), more logic is needed.
                 break 

        else: # Loop finished without break (max_hops exceeded)
            final_status = f"Stopped: Maximum hops ({max_hops}) exceeded during simulation."
            path.append({'hop': current_hop_num, 'type': 'Stopped', 'detail': final_status})

        print(f"\n--- Trace Finished: {final_status} ---")
        return path, final_status


    # --- Helper for Connectivity Tree (Alternative Text Output) ---
    def _get_interface_policy_refs(self, interface_name):
        """Find policies referencing a given interface or its zone."""
        policy_refs = {'src': [], 'dst': []}
        zone = next((z_name for z_name, z_data in self.model.zones.items() 
                     if interface_name in z_data.get('interface', [])), None)
        match_candidates = {interface_name, zone} if zone else {interface_name}

        for policy in self.model.policies:
            if policy.get('status') != 'disable':
                 p_id = policy.get('id', 'N/A')
                 if set(policy.get('srcintf', [])).intersection(match_candidates):
                     policy_refs['src'].append(p_id)
                 if set(policy.get('dstintf', [])).intersection(match_candidates):
                     policy_refs['dst'].append(p_id)
                      
        # Sort by ID numerically
        policy_refs['src'] = sorted([int(p) for p in policy_refs['src'] if p.isdigit()])
        policy_refs['dst'] = sorted([int(p) for p in policy_refs['dst'] if p.isdigit()])
        return policy_refs

    def generate_connectivity_tree(self):
        """Generates a text-based tree showing interface connectivity and policy references."""
        output_lines = ["--- Interface Connectivity & Policy Tree ---"]
        processed_interfaces = set()
        indent_char = "  " # Basic indent unit
        connector = "|-- "
        last_connector = "`-- "
        space = "|   "
        last_space = "    "
        
        # --- Nested Helper Function --- 
        def format_interface_details(intf_name, indent_prefix, is_last_item):
            details = [] 
            intf_data = self.model.interfaces.get(intf_name)
            conn = last_connector if is_last_item else connector
            child_prefix = indent_prefix + (last_space if is_last_item else space)
            
            if not intf_data:
                 details.append(f"{indent_prefix}{conn}Interface: {intf_name} (Data Missing!)")
                 return "\n".join(details)

            ip_info = intf_data.get('ip', 'DHCP/Unassigned')
            role = intf_data.get('role', 'N/A')
            alias = intf_data.get('alias')
            desc = intf_data.get('description')
            status = intf_data.get('status', 'unknown')
            vdom = intf_data.get('vdom', 'root')
            
            header = f"{indent_prefix}{conn}Interface: {intf_name} (VDOM: {vdom}, Status: {status})"
            if alias: header += f" (Alias: {alias})"
            details.append(header)
            
            details.append(f"{child_prefix}{connector}IP: {ip_info}")
            # Show secondary IPs if they exist
            secondary_ips = intf_data.get('secondary_ip', [])
            if isinstance(secondary_ips, list) and secondary_ips:
                details.append(f"{child_prefix}{connector}Secondary IPs:")
                sec_ip_prefix = child_prefix + space
                for idx, sec_ip_info in enumerate(secondary_ips):
                    is_last_sec = (idx == len(secondary_ips) - 1)
                    sec_conn = last_connector if is_last_sec else connector
                    sec_ip_str = sec_ip_info.get('ip', '?')
                    details.append(f"{sec_ip_prefix}{sec_conn}{sec_ip_str}")
                    
            details.append(f"{child_prefix}{connector}Role: {role}")
            if desc: details.append(f"{child_prefix}{connector}Desc: {desc}")
            
            # Get connected network
            network_info = "(No direct subnet found)"
            if 'ip' in intf_data and '/' in intf_data['ip']:
                 try:
                     network = ipaddress.ip_network(intf_data['ip'], strict=False)
                     network_info = f"Network: {network.with_netmask}"
                 except ValueError:
                     network_info = "(Invalid IP format)"
            details.append(f"{child_prefix}{connector}{network_info}")
            
            # Get Static Routes via this interface
            routes_via = [r for r in self.model.routes 
                          if r.get('device') == intf_name and r.get('status') != 'disable']
            if routes_via:
                 details.append(f"{child_prefix}{connector}Static Routes Via This IF:")
                 num_routes = len(routes_via)
                 route_child_prefix = child_prefix + space
                 for idx, r in enumerate(routes_via):
                     is_last_route = (idx == num_routes - 1)
                     route_conn = last_connector if is_last_route else connector
                     dst = r.get('dst','?')
                     gw = r.get('gateway','connected')
                     dist = r.get('distance','?')
                     cmt = r.get('comment')
                     route_str = f"{route_conn}{dst} via {gw} (Dist: {dist})"
                     if cmt: route_str += f" # {cmt}"
                     details.append(f"{route_child_prefix}{route_str}")
            # else:
            #      details.append(f"{child_prefix}{connector}Static Routes Via This IF: (None)")
            
            # Get Policy References
            policy_refs = self._get_interface_policy_refs(intf_name)
            details.append(f"{child_prefix}{last_connector}Policy Refs:")
            policy_child_prefix = child_prefix + last_space
            details.append(f"{policy_child_prefix}  Source In (Policy IDs): {', '.join(map(str, policy_refs['src'])) if policy_refs['src'] else '(None)'}")
            details.append(f"{policy_child_prefix}  Dest Out (Policy IDs): {', '.join(map(str, policy_refs['dst'])) if policy_refs['dst'] else '(None)'}")
            
            return "\n".join(details)
        # --- End of Nested Helper Function ---
        
        # Group interfaces by Zone first
        interfaces_in_zones = set()
        zone_list = sorted(self.model.zones.keys())
        num_zones = len(zone_list)
        
        for i, zone_name in enumerate(zone_list):
            is_last_zone = (i == num_zones - 1)
            zone_prefix_outer = last_connector if is_last_zone else connector
            child_prefix_outer = last_space if is_last_zone else space
            
            output_lines.append(f"{zone_prefix_outer}Zone: {zone_name}")
            zone_data = self.model.zones[zone_name]
            intf_list = sorted([name for name in zone_data.get('interface', []) if name in self.model.interfaces])
            num_intf_in_zone = len(intf_list)

            for j, intf_name in enumerate(intf_list):
                 is_last_in_zone = (j == num_intf_in_zone - 1)
                 output_lines.append(format_interface_details(intf_name, child_prefix_outer, is_last_in_zone))
                 processed_interfaces.add(intf_name)
                 interfaces_in_zones.add(intf_name)

        # List interfaces not belonging to any zone
        standalone_interfaces = sorted([name for name in self.model.interfaces.keys() 
                                     if name not in interfaces_in_zones])
        num_standalone = len(standalone_interfaces)
        if standalone_interfaces:
             output_lines.append("\n--- Interfaces Not in Zones ---")
             for k, intf_name in enumerate(standalone_interfaces):
                 is_last_standalone = (k == num_standalone - 1)
                 # No zone prefix needed here, start directly
                 output_lines.append(format_interface_details(intf_name, "", is_last_standalone))
                 processed_interfaces.add(intf_name)

        return "\n".join(output_lines)
