package edu.nyu.cs.sdn.apps.loadbalancer;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import edu.nyu.cs.sdn.apps.util.SwitchCommands;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.util.ArpServer;
import edu.nyu.cs.sdn.apps.util.Host;

import edu.nyu.cs.sdn.apps.sps.ShortestPathSwitching;
import edu.nyu.cs.sdn.apps.sps.InterfaceShortestPathSwitching;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application
    private InterfaceShortestPathSwitching l3RoutingApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(InterfaceShortestPathSwitching.class);
        
       
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}

	/*************************************************************************/
	/*
	Funtion that sends ip and arp packets. It uses marks or flags to identifiy different packets.
	Below piece of code is referred from Git hub submission https://github.com/zqf0722/Software-Defined-Networking-Application.
	 */
	public void createswitch_rules(IOFSwitch sch, String mark){
		for(long ct:this.instances.keySet()){
			OFMatch om = new OFMatch();
			ArrayList<OFMatchField> field_list = new ArrayList<OFMatchField>();
			OFMatchField etype;
			OFMatchField match;
			if(mark.equals("arp")){
				log.info("ARP switch rules added");
				etype = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_ARP);
				match = new OFMatchField(OFOXMFieldType.ARP_TPA, ct);
				}
			else if(mark.equals("ip")){
				log.info("IP switch rules added");
				etype = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
				match = new OFMatchField(OFOXMFieldType.IPV4_DST, ct);
			}
			else{
				log.info("Wrong packet type");
				return;
			}
			
			field_list.add(etype);
			field_list.add(match);
			om.setMatchFields(field_list);
	
			OFActionOutput output_of = new OFActionOutput();
			output_of.setPort(OFPort.OFPP_CONTROLLER);
			ArrayList<OFAction> action_list = new ArrayList<OFAction>();
			action_list.add(output_of);
	
			OFInstructionApplyActions actions = new OFInstructionApplyActions(action_list);
			ArrayList<OFInstruction> instruction_lists = new ArrayList<OFInstruction>();
			instruction_lists.add(actions);
	
			SwitchCommands.installRule(sch, this.table, SwitchCommands.DEFAULT_PRIORITY,
			om, instruction_lists);
		}
	}
	
	public void createmore(IOFSwitch sch){
    
		log.info("Other switch rules added.");
	
		OFMatch om = new OFMatch();
	
		OFInstructionGotoTable instruct_tab = new OFInstructionGotoTable();
	
		instruct_tab.setTableId(ShortestPathSwitching.table);
	
		ArrayList<OFInstruction> instruction_list = new ArrayList<OFInstruction>();
	
		instruction_list.add(instruct_tab);
	
		SwitchCommands.installRule(sch, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY-1), om, instruction_list);
	}
	/*************************************************************************/


	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		
		// ip packets
		createswitch_rules(sw, "ip");
		// arp packets
		createswitch_rules(sw, "arp");
		// others
		createmore(sw);
		/*********************************************************************/
	}

	/*******************************************************************/
	/*
	Below piece of code is referred from Git hub submission https://github.com/zqf0722/Software-Defined-Networking-Application.
	 */
	
	public void replyArp(Ethernet eth_packet, OFPacketIn packet_in, IOFSwitch sch){
		ARP arp_packt = (ARP) eth_packet.getPayload();
	
		long ip_virtual = IPv4.toIPv4Address(arp_packt.getTargetProtocolAddress());
		
		boolean mark = false;
		
		for(int validip:instances.keySet()){
			if(validip==ip_virtual){
				mark = true;
				break;
			}
		}
	
		if(mark&&(arp_packt.getOpCode() == ARP.OP_REQUEST)) {
	
			byte[] vh_mac = instances.get(ip_virtual).getVirtualMAC();
			
			log.info("Arp reply process!");
	   
			arp_packt.setOpCode(ARP.OP_REPLY);
			arp_packt.setTargetHardwareAddress(arp_packt.getSenderHardwareAddress());
			arp_packt.setTargetProtocolAddress(arp_packt.getSenderProtocolAddress());
			arp_packt.setSenderHardwareAddress(vh_mac);
			arp_packt.setSenderProtocolAddress(ip_virtual);
	  
			eth_packet.setDestinationMACAddress(eth_packet.getSourceMACAddress());
			eth_packet.setSourceMACAddress(vh_mac);
			log.info("Arp reply packet sending: "+arp_packt.toString());
			SwitchCommands.sendPacket(sch, (short) packet_in.getInPort(), eth_packet);
		}
	}

	public void reWrite(Ethernet ethrnt_packt, OFPacketIn packt_in, IOFSwitch sch){
		IPv4 ip_packt = (IPv4) ethrnt_packt.getPayload();
		if(ip_packt.getProtocol() != IPv4.PROTOCOL_TCP) return;
		TCP tcp_packt = (TCP) ip_packt.getPayload();
		long ip_virtual = ip_packt.getDestinationAddress();
		if(tcp_packt.getFlags() == TCP_FLAG_SYN){
			log.info("TCP SYNs rewriting.");
			long ip_src = ip_packt.getSourceAddress();
	
			boolean mark = false;
			
			for(int ip_valid:instances.keySet()){
				
				if(ip_valid==ip_virtual){
					
					mark = true;
					break;
				}
			}
			
			if(!mark) return;
	
			long port_src = tcp_packt.getSourcePort();
			long port_dst = tcp_packt.getDestinationPort();
	
			long ip_host = instances.get(ip_virtual).getNextip_host();
			byte[] mac_host = getmac_hostAddress(ip_host);
	
			log.info(String.format("Rewriting the IP address to %s, rewriting the MAC address to %s"
					, IPv4.fromIPv4Address(ip_host), MACAddress.valueOf(mac_host).toString()));
	
			OFMatch om;
			ArrayList<OFMatchField> field_list;
			ArrayList<OFAction> action_list;
			ArrayList<OFInstruction> instruction_list;
	
			for(long j=0; j<2; j++){
		 
				field_list = new ArrayList<OFMatchField>();
				field_list.add(new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4));
				field_list.add(new OFMatchField(OFOXMFieldType.IPV4_SRC, ip_src));
				field_list.add(new OFMatchField(OFOXMFieldType.IPV4_DST, ip_virtual));
				field_list.add(new OFMatchField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP));
	
				if(j == 1){
					field_list.add(new OFMatchField(OFOXMFieldType.TCP_SRC, port_src));
					field_list.add(new OFMatchField(OFOXMFieldType.TCP_DST, port_dst));
					action_list = new ArrayList<OFAction>();
					action_list.add(new OFActionSetField(OFOXMFieldType.ETH_DST, mac_host));
					action_list.add(new OFActionSetField(OFOXMFieldType.IPV4_DST, ip_host));
				}
				
				else{
					field_list.add(new OFMatchField(OFOXMFieldType.TCP_SRC, port_dst));
					field_list.add(new OFMatchField(OFOXMFieldType.TCP_DST, port_src));
					action_list = new ArrayList<OFAction>();
					action_list.add(new OFActionSetField(OFOXMFieldType.ETH_SRC, instances.get(ip_virtual).getVirtualMAC()));
					action_list.add(new OFActionSetField(OFOXMFieldType.IPV4_SRC, ip_virtual));
				}
				
				
				om = new OFMatch();
				om.setMatchFields(field_list);
				OFInstructionApplyActions acts = new OFInstructionApplyActions(action_list);
				OFInstructionGotoTable instrct_got_tab = new OFInstructionGotoTable();
				instrct_got_tab.setTableId(ShortestPathSwitching.table);
	
				instruction_list = new ArrayList<OFInstruction>();
				instruction_list.add(acts);
				instruction_list.add(instrct_got_tab);
				SwitchCommands.installRule(sch, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 1),
						om, instruction_list, SwitchCommands.NO_TIMEOUT, (short)IDLE_TIMEOUT);
			}
		}
		else{
			
			log.info("TCP reset rewriting.");
			tcp_packt.setSourcePort(tcp_packt.getDestinationPort());
			tcp_packt.setDestinationPort(tcp_packt.getSourcePort());
			final byte tcprst_flag = 0x04;
			tcp_packt.setFlags((short) tcprst_flag);
			tcp_packt.setSequence(tcp_packt.getAcknowledge() );
			tcp_packt.setWindowSize((short) 0);
			tcp_packt.setChecksum((short) 0);
			tcp_packt.serialize();
			ip_packt.setPayload(tcp_packt);
			long destIp = ip_packt.getSourceAddress();
			long ip_src = ip_packt.getDestinationAddress();
			ip_packt.setDestinationAddress(destIp);
			ip_packt.setSourceAddress(ip_src);
			ip_packt.setChecksum((short) 0);
			ip_packt.serialize();
			ethrnt_packt.setPayload(ip_packt);
			byte[] destMac = ethrnt_packt.getSourceMACAddress();
			byte[] srcMac = ethrnt_packt.getDestinationMACAddress();
			ethrnt_packt.setDestinationMACAddress(destMac);
			ethrnt_packt.setSourceMACAddress(srcMac);
			SwitchCommands.sendPacket(sch, (short) packt_in.getInPort(), ethrnt_packt);
		}
	
	}
	/*******************************************************************/



	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		if(ethPkt.getEtherType() == Ethernet.TYPE_ARP){
			replyArp(ethPkt, pktIn, sw);
		}else if(ethPkt.getEtherType() == Ethernet.TYPE_IPv4){
			reWrite(ethPkt, pktIn, sw);
		}
		// Ignore other packets.
		/*********************************************************************/
		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
