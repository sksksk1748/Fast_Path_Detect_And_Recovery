# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER # 2020/12/06 shortest path add "DEAD_DISPATCHERby" by tim
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp
from ryu.lib.packet import ipv4

from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib

#2020/12/06 shortest path by tim
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link, get_switch, get_link
from ryu.controller import dpset
from threading import Lock
#2020/12/06 shortest path by tim

import copy
import json
import time
"""
2020/12/05 test http link by tim
"""
test_tmp = 0  # for line 355
test_tmp2 = 0 # for line 356
"""
2020/12/05 test http link by tim
"""
#2020/12/06 shortest path by tim
UP = 1
DOWN = 0
#2020/12/06 shortest path by tim
simple_switch_instance_name = 'simple_switch_api_app'
url = '/switch/'
class mySwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):

        super(mySwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}   #mac_to_port[dpid][src] : in_port
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController, {simple_switch_instance_name : self})
        self.datapaths={}   #datapaths[dpid] : datapath
        self.flow_table={}  #flow_table[dpid] : flows
        self.switch={}      #switch[dpdi] : switch_features
        self.port={}        #port[dpid][port] : port_desc_stats
        self.link={}        #link[switch][port] : switch,port
        self.host={}
        
        #2020/12/06 shortest path by tim
        self.topo_shape = TopoStructure()
        #2020/12/06 shortest path by tim
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[str(datapath.id)]=datapath
        tmp={}
        msg=ev.msg
        tmp["datapath_id"]=msg.datapath_id
        tmp["n_buffers"]=msg.n_buffers
        tmp["n_tables"]=msg.n_tables
        tmp["auxiliary_id"]=msg.auxiliary_id
        tmp["capabilities"]=msg.capabilities
        self.switch[str(datapath.id)]=tmp
        
        self.send_port_desc_stats_request(datapath)
        
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)
    
    def link_discovery(self):

        for dpid in self.datapaths:
            for port in self.port[dpid]:
                if port != "4294967294":
                    #self.logger.info("========== [%s] [%s] ", dpid, port)
                    self.send_lldp(self.datapaths[dpid],int(port),self.port[dpid][port]["hw_addr"])

    def send_lldp(self, datapath, port_no, hw_addr):
        ofp=datapath.ofproto
        pkt=packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_LLDP, src=hw_addr, dst=lldp.LLDP_MAC_NEAREST_BRIDGE))

        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id=str(datapath.id))
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=str(port_no))
        tlv_ttl = lldp.TTL(ttl=10)
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        pkt.add_protocol(lldp.lldp(tlvs))
        pkt.serialize()

        data = pkt.data
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=port_no)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
        
        datapath.send_msg(out)
   
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = hard_timeout = 0
        buffer_id = ofproto.OFP_NO_BUFFER
        actions = []
        inst = []
        req = parser.OFPFlowMod(datapath, match= match, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPG_ANY,out_group=ofproto.OFPG_ANY)
        
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # 2020/12/06 shortest path by tim
        """
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            pkt=pkt.get_protocol(lldp.lldp)
            lldp_switchID=pkt.tlvs[0].chassis_id
            lldp_portID=pkt.tlvs[1].port_id
            if datapath.id > int(lldp_switchID):
                if lldp_switchID not in self.link:
                    self.link[lldp_switchID]=[]
            
                tmp={lldp_portID:[str(datapath.id), str(in_port)]}
                self.link[lldp_switchID].append(tmp)
                print "(",lldp_switchID, lldp_portID,") -> (",datapath.id,in_port,")"
            return
        """
        # 2020/12/06 shortest path by tim
        dst = eth.dst
        src = eth.src
        eth_type=eth.ethertype

        dpid = datapath.id
        if eth_type==2048:
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            ipv4_src=ip.src
            ipv4_dst=ip.dst
            ip_proto=ip.proto

        self.mac_to_port.setdefault(dpid, {})

        # 2020/12/06 shortest path by tim
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        if eth_type==0x0800 and ipv4_src not in self.host:
           self.host[ipv4_src]={"switch":dpid,"port":in_port,"mac":eth.src}
            

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if eth_type==0x0800:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth_type, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, ip_proto=ip_proto)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth_type)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def send_flow_stats_request(self,dpid):
        for datapath in self.datapaths.values():
            if datapath.id == int(dpid):
                ofp = datapath.ofproto
                parser = datapath.ofproto_parser
                req=parser.OFPFlowStatsRequest(datapath)
        
                datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply,MAIN_DISPATCHER)
    def flow_stat_reply_handler(self,ev):
        
        total_flows=[]
        for stat in ev.msg.body:
            flows={}
            flows['table_id']=stat.table_id
            flows['duration_sec']=stat.duration_sec
            flows['priority']=stat.priority
            flows['idle_timeout']=stat.idle_timeout
            flows['hard_timeout']=stat.hard_timeout
            flows['flags']=stat.flags
            flows['cookie']=stat.cookie
            flows['packet_count']=stat.packet_count
            flows['byte_count']=stat.byte_count
            flows['match']={}

            if 'eth_dst' in stat.match:
                flows['match']['eth_dst']=stat.match['eth_dst']
            if 'eth_src' in stat.match:
                flows['match']['eth_src']=stat.match['eth_src']
            if 'eth_type' in stat.match:
                flows['match']['eth_type']=stat.match['eth_type']
            if 'ipv4_dst' in stat.match:
                flows['match']['ipv4_dst']=stat.match['ipv4_dst']
            if 'ipv4_src' in stat.match:
                flows['match']['ipv4_src']=stat.match['ipv4_src']
            
            flows['instructions']={}
            if stat.instructions:
                flows['instructions']['outport']=stat.instructions[0].actions[0].port
            total_flows.append(flows)    
        self.flow_table[str(ev.msg.datapath.id)]=total_flows
    
    def send_port_desc_stats_request(self,datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        self.port[str(ev.msg.datapath.id)]={}
        for p in ev.msg.body:
            tmp={}
            tmp["port_no"]=p.port_no
            tmp["hw_addr"]=p.hw_addr
            tmp["name"]=p.name
            tmp["config"]=p.config
            tmp["state"]=p.state
            tmp["curr"]=p.curr
            tmp["advertised"]=p.advertised
            tmp["supported"]=p.supported
            tmp["peer"]=p.peer
            tmp["curr_speed"]=p.curr_speed
            tmp["max_speed"]=p.max_speed
            self.port[str(ev.msg.datapath.id)][str(p.port_no)]=tmp
    
    #2020/12/06 shortest path by tim
    """
    EventOFPPortStatus: An event class for switch port status notification.
    The bellow handles the event.
    """
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        #self.logger.info("[Ehsan] Received EventOFPPortStatus")

        """ Port status message
        The switch notifies controller of change of ports.
        Attribute     |     Description
        --------------------------------
        reason        |     One of the following values.
                      |     OFPPR_ADD
                      |     OFPPR_DELETE
                      |     OFPPR_MODIFY
        --------------------------------
        desc          |     instance of OFPPort
        """
        msg = ev.msg
        dp = msg.datapath
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("\tport added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("\tport deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("\tport modified %s", port_no)
            dp_str = dpid_lib.dpid_to_str(dp.id)
            self.logger.info("\t[Ehsan] Sending send_port_desc_stats_request to datapath id : " + dp_str)
            self.send_port_desc_stats_request(dp)
            """
            2020/12/05 test http link by tim
            """
            global test_tmp 
            global test_tmp2 
            #test_tmp = 0
            #test_tmp2 = 0
            test_tmp = port_no
            test_tmp2 = dp_str
            """
            2020/12/05 test http link by tim
            """
        else:
            self.logger.info("\tIlleagal port state %s %s", port_no, reason)
    #2020/12/06 shortest path by tim

    """
    2020/12/05 test http link by tim
    """
    def linkdown_discovery(self):
        return test_tmp, test_tmp2
    """
    2020/12/05 test http link by tim
    """

    ###################################################################################
    #2020/12/06 shortest path by tim ,for class TopoStructure() Line 622
    ###################################################################################
    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        self.topo_shape.topo_raw_switches = copy.copy(get_switch(self, None))
        self.topo_shape.topo_raw_links = copy.copy(get_link(self, None))

        self.topo_shape.print_links("EventSwitchEnter")
        self.topo_shape.print_switches("EventSwitchEnter")

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")

    """
    This function determines the links and switches currently in the topology
    """
    def get_topology_data(self):
        # Call get_switch() to get the list of objects Switch.
        self.topo_shape.topo_raw_switches = copy.copy(get_all_switch(self))

        # Call get_link() to get the list of objects Link.
        self.topo_shape.topo_raw_links = copy.copy(get_all_link(self))

        self.topo_shape.print_links("get_topology_data")
        self.topo_shape.print_switches("get_topology_data")

    """
    EventOFPPortStatus: An event class for switch port status notification.
    The bellow handles the event.
    """
    @set_ev_cls(dpset.EventPortModify, MAIN_DISPATCHER)
    def port_modify_handler(self, ev):
        self.topo_shape.lock.acquire()
        dp = ev.dp
        port_attr = ev.port
        dp_str = dpid_lib.dpid_to_str(dp.id)
        self.logger.info("\t ***switch dpid=%s"
                         "\n \t port_no=%d hw_addr=%s name=%s config=0x%08x "
                         "\n \t state=0x%08x curr=0x%08x advertised=0x%08x "
                         "\n \t supported=0x%08x peer=0x%08x curr_speed=%d max_speed=%d" %
                         (dp_str, port_attr.port_no, port_attr.hw_addr,
                          port_attr.name, port_attr.config,
                          port_attr.state, port_attr.curr, port_attr.advertised,
                          port_attr.supported, port_attr.peer, port_attr.curr_speed,
                          port_attr.max_speed))
        if port_attr.state == 1:
            tmp_list = []
            removed_link = self.topo_shape.link_with_src_port(port_attr.port_no, dp.id)
            for i, link in enumerate(self.topo_shape.topo_raw_links):
                if link.src.dpid == dp.id and link.src.port_no == port_attr.port_no:
                    print "\t Removing link " + str(link) + " with index " + str(i)
                    # del self.topo_shape.topo_raw_links[i]
                elif link.dst.dpid == dp.id and link.dst.port_no == port_attr.port_no:
                    print "\t Removing link " + str(link) + " with index " + str(i)
                    # del self.topo_shape.topo_raw_links[i]
                else:
                    tmp_list.append(link)

            self.topo_shape.topo_raw_links = copy.copy(tmp_list)

            self.topo_shape.print_links("Link Down")

            print "\t Considering the removed Link " + str(removed_link)
            if removed_link is not None:
                shortest_path_hubs, shortest_path_node = self.topo_shape.find_shortest_path(removed_link.src.dpid)
                print("\t\tNew shortest_path_hubs: {0}\n\t\tNew shortest_path_node: {1}".format(shortest_path_hubs, shortest_path_node))
        elif port_attr.state == 0:
            self.topo_shape.print_links("Link Up")
        self.topo_shape.lock.release()

    ###################################################################################
    #2020/12/06 shortest path by tim ,for class TopoStructure() Line 622
    ###################################################################################

class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simpl_switch_spp = data[simple_switch_instance_name]

    @route('simpleswitch', url+'flowtable/{dpid}', methods=['GET'])
    def get_flow_table(self, req, **kwargs):
        simple_switch=self.simpl_switch_spp
        dpid = kwargs['dpid']

        simple_switch.send_flow_stats_request(dpid)
        time.sleep(0.1)
        body = json.dumps(simple_switch.flow_table[dpid])
        return Response(content_type='application/json', body=body)

    @route('simpleswitch', url+'flowtable/{dpid}', methods=['POST'])
    def set_flow_table(self, req, **kwargs):
        simple_switch=self.simpl_switch_spp
        dpid=kwargs['dpid']
        flow=json.loads(req.body)

        datapath=simple_switch.datapaths[dpid]
        parser = datapath.ofproto_parser
        
        match_dic={}
        if 'eth_type' in flow : match_dic['eth_type']=int(flow['eth_type'],16)
        if 'in_port' in flow : match_dic['in_port']=int(flow['in_port'])
        if 'ipv4_src' in flow : match_dic['ipv4_src']=flow['ipv4_src']
        if 'ipv4_dst' in flow : match_dic['ipv4_dst']=flow['ipv4_dst']
        if 'eth_src' in flow : match_dic['eth_src']=flow['eth_src']
        if 'eth_dst' in flow : match_dic['eth_dst']=flow['eth_dst']
        
        match=parser.OFPMatch(**match_dic)
        actions = []
        simple_switch.add_flow(datapath, 0, match, actions)
    
    @route('simpleswitch', url+'flowtable/{dpid}', methods=['DELETE'])
    def del_flow_table(self, req, **kwargs):
        simple_switch=self.simpl_switch_spp
        dpid=kwargs['dpid']
        flow=json.loads(req.body)

        datapath=simple_switch.datapaths[dpid]
        parser = datapath.ofproto_parser
        
        match_dic={}
        if 'eth_type' in flow : match_dic['eth_type']=int(flow['eth_type'],16)
        if 'in_port' in flow : match_dic['in_port']=int(flow['in_port'])
        if 'ipv4_src' in flow : match_dic['ipv4_src']=flow['ipv4_src']
        if 'ipv4_dst' in flow : match_dic['ipv4_dst']=flow['ipv4_dst']
        if 'eth_src' in flow : match_dic['eth_src']=flow['eth_src']
        if 'eth_dst' in flow : match_dic['eth_dst']=flow['eth_dst']
        
        match=parser.OFPMatch(**match_dic)
        simple_switch.del_flow(datapath,match)
    
    @route('simpleswitch', url+'switchDPID', methods=['GET'])
    def get_switch_dpid(self, req, **kwargs):
        simple_switch=self.simpl_switch_spp
        body = json.dumps(simple_switch.switch)
        return Response(content_type='application/json', body=body)
   
    @route('simpleswitch', url+'switch/{dpid}', methods=['GET'])
    def get_switch_desc(self, req, **kwargs):
        simple_switch=self.simpl_switch_spp
        dpid = kwargs['dpid']
        body=json.dumps(simple_switch.switch[dpid])
        return Response(content_type='application/json', body=body)
    
    @route('simpleswitch', url+'portID', methods=['GET'])
    def get_port_id(self, req, **kwargs):
        simple_switch=self.simpl_switch_spp
        body = json.dumps(simple_switch.port)
        return Response(content_type='application/json', body=body)
    
    @route('simpleswitch', url+'port/{dpid}/{port}', methods=['GET'])
    def get_port_desc(self, req, **kwargs):
        simple_switch=self.simpl_switch_spp
        dpid = kwargs['dpid']
        port = kwargs['port']
        
        simple_switch.send_port_desc_stats_request(simple_switch.datapaths[dpid])
        time.sleep(0.1)
        body = json.dumps(simple_switch.port[dpid][port])
        return Response(content_type='application/json', body=body)

    @route('simpleswitch', url+'link', methods=['GET'])
    def get_link(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        simple_switch.link = {}
        simple_switch.link_discovery()
        time.sleep(0.1)
        body = json.dumps(simple_switch.link)
        return Response(content_type='application/json', body=body)

    """
    2020/12/05 test http link by tim
    """
    @route('simpleswitch', url+'link_down', methods=['GET'])
    def get_linkdown(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        """
        2020/12/05 test http link by tim
        """
        a ,b = simple_switch.linkdown_discovery()
        simple_switch.link = {a: [b]}
        """
        2020/12/05 test http link by tim
        """
        time.sleep(0.1)
        body = json.dumps(simple_switch.link)
        return Response(content_type='application/json', body=body)
    """
    2020/12/05 test http link by tim
    """

    @route('simpleswitch', url+'host', methods=['GET'])
    def get_host(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        body = json.dumps(simple_switch.host)
        return Response(content_type='application/json', body=body)

    @route('simpleswitch', url+'saveflow/{dpid}', methods=['POST'])
    def save_flow(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        dpid=kwargs['dpid']
        filename=req.body
        simple_switch.send_flow_stats_request(dpid)
        time.sleep(0.1)
        f=open(filename,"w")
        flows=[]
        for flow in simple_switch.flow_table[dpid]:
            tmp={}
            tmp['instructions']=flow['instructions']
            tmp['match']=flow['match']
            tmp['priority']=flow['priority']
            flows.append(tmp)
        json.dump(flows, f, indent=4, sort_keys=True)
        f.close()

    @route('simpleswitch', url+'loadflow/{dpid}', methods=['POST'])
    def load_flow(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        dpid=kwargs['dpid']
        datapath=simple_switch.datapaths[dpid]
        parser=datapath.ofproto_parser
        match=parser.OFPMatch()
        simple_switch.del_flow(datapath,match)
        filename=req.body
        f=open(filename,"r")
        flows=json.load(f)
        for flow in flows:
            match=parser.OFPMatch(**flow['match'])
            #match=parser.OFPMatch()
            if flow['instructions']:
                actions = [parser.OFPActionOutput(port=int(flow['instructions']['outport']))]
            else:
                actions = []
            simple_switch.add_flow(datapath, flow['priority'], match, actions)
        f.close()

#2020/12/06 shortest path by tim
"""
This class holds the list of links and switches in the topology and it provides some useful functions
"""
class TopoStructure():
    def __init__(self, *args, **kwargs):
        self.topo_raw_switches = []
        self.topo_raw_links = []
        self.topo_links = []
        self.lock = Lock()

    def print_links(self, func_str=None):
        # Convert the raw link to list so that it is printed easily
        print(" \t" + str(func_str) + ": Current Links:")
        for l in self.topo_raw_links:
            print (" \t\t" + str(l))

    def print_switches(self, func_str=None):
        print(" \t" + str(func_str) + ": Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t" + str(s))

    def switches_count(self):
        return len(self.topo_raw_switches)

    def convert_raw_links_to_list(self):
        # Build a  list with all the links [((srcNode,port), (dstNode, port))].
        # The list is easier for printing.
        self.topo_links = [((link.src.dpid, link.src.port_no),
                            (link.dst.dpid, link.dst.port_no))
                           for link in self.topo_raw_links]

    def convert_raw_switch_to_list(self):
        # Build a list with all the switches ([switches])
        self.topo_switches = [(switch.dp.id, UP) for switch in self.topo_raw_switches]

    """
    Adds the link to list of raw links
    """
    def bring_up_link(self, link):
        self.topo_raw_links.append(link)

    """
    Check if a link with specific nodes exists.
    """
    def check_link(self, sdpid, sport, ddpid, dport):
        for i, link in self.topo_raw_links:
            if ((sdpid, sport), (ddpid, dport)) == (
                    (link.src.dpid, link.src.port_no), (link.dst.dpid, link.dst.port_no)):
                return True
        return False

    """
    Finds the shortest path from source s to all other nodes.
    Both s and d are switches.
    """
    def find_shortest_path(self, s):
        # I really recommend watching this video: https://www.youtube.com/watch?v=zXfDYaahsNA
        s_count = self.switches_count()
        s_temp = s

        # If you wanna see the prinfs set this to one.
        verbose = 0

        visited = []

        Fereng = []
        Fereng.append(s_temp)

        # Records number of hubs which you can reach the node from specified src
        shortest_path_hubs = {}
        # The last node which you can access the node from. For example: {1,2} means you can reach node 1 from node 2.
        shortest_path_node = {}
        shortest_path_hubs[s_temp] = 0
        shortest_path_node[s_temp] = s_temp
        while s_count > len(visited):
            if verbose == 1: print "visited in: " + str(visited)
            visited.append(s_temp)
            if verbose == 1: print ("Fereng in: " + str(Fereng))
            if verbose == 1: print ("s_temp in: " + str(s_temp))
            for l in self.find_links_with_src(s_temp):
                if verbose == 1: print "\t" + str(l)
                if l.dst.dpid not in visited:
                    Fereng.append(l.dst.dpid)
                if verbose == 1: print ("\tAdded {0} to Fereng: ".format(l.dst.dpid))
                if l.dst.dpid in shortest_path_hubs:
                    # Find the minimum o
                    if shortest_path_hubs[l.src.dpid] + 1 < shortest_path_hubs[l.dst.dpid]:
                        shortest_path_hubs[l.dst.dpid] = shortest_path_hubs[l.src.dpid] + 1
                        shortest_path_node[l.dst.dpid] = l.src.dpid
                    else:
                        shortest_path_hubs[l.dst.dpid] = shortest_path_hubs[l.dst.dpid]

                    if verbose == 1: print(
                        "\t\tdst dpid found in shortest_path. Count: " + str(shortest_path_hubs[l.dst.dpid]))
                elif l.src.dpid in shortest_path_hubs and l.dst.dpid not in shortest_path_hubs:
                    if verbose == 1: print("\t\tdst dpid not found bit src dpid found.")
                    shortest_path_hubs[l.dst.dpid] = shortest_path_hubs[l.src.dpid] + 1
                    shortest_path_node[l.dst.dpid] = l.src.dpid
            if verbose == 1:
                print ("shortest_path Hubs: " + str(shortest_path_hubs))
                print ("shortest_path Node: " + str(shortest_path_node))
            if s_temp in Fereng:
                Fereng.remove(s_temp)
            #min_val = min(Fereng)
            if verbose == 1: print ("Fereng out: " + str(Fereng))
            t_dpid = [k for k in Fereng if k not in visited]
            if verbose == 1: print ("Next possible dpids (t_dpid): " + str(t_dpid))

            if len(t_dpid) != 0:
                s_temp = t_dpid[t_dpid.index(min(t_dpid))]

            if verbose == 1: print "s_temp out: " + str(s_temp)
            if verbose == 1: print "visited out: " + str(visited) + "\n"
        return shortest_path_hubs, shortest_path_node

    """
    Find a path between src and dst based on the shorted path info which is stored on shortest_path_node
    """
    def find_path_from_topo(self,src_dpid, dst_dpid, shortest_path_node):
        path = []
        now_node = dst_dpid
        last_node = None
        while now_node != src_dpid:
            last_node = shortest_path_node.pop(now_node, None)
            if last_node != None:
                l = self.link_from_src_to_dst(now_node, last_node)
                if l is None:
                    print("Link between {0} and {1} was not found in topo.".format(now_node, last_node))
                else:
                    path.append(l)
                    now_node = last_node
            else:
                print "Path could not be found"
        return path
    """
    Finds the dpids of destinations where the links' source is s_dpid
    """
    def find_dst_with_src(self, s_dpid):
        d = []
        for l in self.topo_raw_links:
            if l.src.dpid == s_dpid:
                d.append(l.dst.dpid)
        return d

    """
    Finds the list of link objects where links' src dpid is s_dpid
    """
    def find_links_with_src(self, s_dpid):
        d_links = []
        for l in self.topo_raw_links:
            if l.src.dpid == s_dpid:
                d_links.append(l)
        return d_links

    """
    Returns a link object that has in_dpid and in_port as either source or destination dpid and port.
    """
    def link_with_src_dst_port(self, in_port, in_dpid):
        for l in self.topo_raw_links:
            if (l.src.dpid == in_dpid and l.src.port_no == in_port) or (
                            l.dst.dpid == in_dpid and l.src.port_no == in_port):
                return l
        return None
    """
    Returns a link object from src with dpid s to dest with dpid d.
    """
    def link_from_src_to_dst(self, s, d):
        for l in self.topo_raw_links:
            if l.src.dpid == s and l.dst.dpid == d:
                return l
        return None
    """
    Returns a link object that has in_dpid and in_port as either source dpid and port.
    """
    def link_with_src_port(self, in_port, in_dpid):
        for l in self.topo_raw_links:
            if (l.src.dpid == in_dpid and l.src.port_no == in_port) or (l.dst.dpid == in_dpid and l.src.port_no == in_port):
                return l
        return None

    ########## Functions related to Spanning Tree Algorithm ##########
    def find_root_switch(self):
        pass

#2020/12/06 shortest path by tim