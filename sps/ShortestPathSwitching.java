package edu.nyu.cs.sdn.apps.sps;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/*
	Packets needed to match IP packets whose destination MAC is the MAC address assigned to host h
 */
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionType;

import edu.nyu.cs.sdn.apps.util.Host;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.packet.Ethernet;

public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching
{
	public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    public static byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

	// Map that stores the predecessor of a switch along the shortest path from the key to that switch
	private HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> paths;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
		
		
		this.paths = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();
        
        /*********************************************************************/
	}


	/*************************************************************************/
	/*
		Below pieces of code is referred from Git hub submission https://github.com/zqf0722/Software-Defined-Networking-Application.
	 */

	public HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> bf_shortest_path() {
		Collection<IOFSwitch> swtchs = getSwitches().values();
		HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> shortest_path = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();
		for(IOFSwitch x : swtchs) {
			HashMap<IOFSwitch, Integer> hm = new HashMap<IOFSwitch, Integer>();
			HashMap<IOFSwitch, IOFSwitch> prdcsr = new HashMap<IOFSwitch, IOFSwitch>();
			for(IOFSwitch z : swtchs) {
				hm.put(z, Integer.MAX_VALUE - 1);
				prdcsr.put(z, null);
			}
			hm.put(x, 0);
			for(int i=0;i<swtchs.size()-1;i++){
				for(Link link : getLinks()) {
					IOFSwitch src = getSwitches().get(link.getSrc());
					IOFSwitch dst = getSwitches().get(link.getDst());
					if(hm.get(src) +1 < hm.get(dst)) {
						hm.put(dst, hm.get(src)+1);
						prdcsr.put(dst, src);
					}else if(hm.get(dst) +1 < hm.get(src)){
						hm.put(src, hm.get(dst)+1);
						prdcsr.put(src, dst);
					}
				}
			}
			shortest_path.put(x, prdcsr);
		}
		return shortest_path;
	}
	/********************************************************************/


	/********************************************************************/

	 private void log_data() {
    
		StringBuilder msg = new StringBuilder();
	
		msg.append("\n##################### LOG DATA #######################################");
		msg.append(get_sp_string(this.paths));
		
		log.info(msg.toString());
	}


	private String get_sp_string(HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> shortest_path) {
		
		StringBuilder msg = new StringBuilder();
		
		msg.append("\n#############ShortestPaths#############\n");
	
			for (Map.Entry<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> inr : shortest_path.entrySet()) {
				Iterator<Map.Entry<IOFSwitch, IOFSwitch>> itr2 = inr.getValue().entrySet().iterator();
				msg.append(inr.getKey().getStringId()).append(": {");
				msg.append("\n");
	
				while (itr2.hasNext()) {
					Map.Entry<IOFSwitch, IOFSwitch> inr2 = itr2.next();
					msg.append("{ ");
	
					if (inr2.getKey() != null && inr2.getKey().getStringId() != null) {
						msg.append(inr2.getKey().getStringId());
					} else {
						msg.append("null");
					}
					msg.append(" : ");
	
					if (inr2.getValue() != null) {
						msg.append(inr2.getValue().getStringId());
					} else {
						msg.append("null");
					}
					msg.append(", ");
					msg.append("}\n");
				}
				msg.append("}\n");
			}
	
			return msg.toString();
		}
	/********************************************************************/


	/**
     * Below pieces of code is referred from Git hub submission https://github.com/zqf0722/Software-Defined-Networking-Application.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		
		this.paths = bf_shortest_path();
	}
	
	
	public byte getTable()
	{ return table; }
	
   
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	

	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	

    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }


	/****************************************************************/
	/*
		Below pieces of code is referred from Git hub submission https://github.com/zqf0722/Software-Defined-Networking-Application.
	*/
	public void set_flow(Host hst) {

		if(hst.isAttachedToSwitch()) {
	
			IOFSwitch s_hst = hst.getSwitch();
			OFMatch om = new OFMatch();
			ArrayList<OFMatchField> listofField = new ArrayList<OFMatchField>();
			OFMatchField etype = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
			OFMatchField mac = new OFMatchField(OFOXMFieldType.ETH_DST, Ethernet.toByteArray(hst.getMACAddress()));
			listofField.add(etype);
			listofField.add(mac);
			om.setMatchFields(listofField);
	
			for(IOFSwitch shc : getSwitches().values()) {
				OFActionOutput out_ofa = new OFActionOutput();
				if(shc.getId() == s_hst.getId()) {
					out_ofa.setPort(hst.getPort());
				} else {
					if(this.paths.containsKey(s_hst)&&this.paths.get(s_hst).containsKey(s)) {
						IOFSwitch prd = this.paths.get(s_hst).get(s);
						for (Link lnk : getLinks()) {
							if ((prd.getId() == lnk.getDst()) && (shc.getId() == lnk.getSrc())) {
								out_ofa.setPort(lnk.getSrcPort());
							}
						}
					}
				}
				
				ArrayList<OFAction> action_list = new ArrayList<OFAction>();
				ArrayList<OFInstruction> instruction_list = new ArrayList<OFInstruction>();
				action_list.add(out_ofa);
				instruction_list.add(new OFInstructionApplyActions(action_list));
				SwitchCommands.installRule(s, table, SwitchCommands.DEFAULT_PRIORITY, om, instruction_list,
						SwitchCommands.NO_TIMEOUT, SwitchCommands.NO_TIMEOUT);
			}
		}
	}

	public void create_flow_tabs() {
    
		for(Host hst : getHosts()) {
	
			set_flow(hst);
			
		}
	}


	public void del_flow(Host hst) {
    
		OFMatch om = new OFMatch();
		ArrayList<OFMatchField> field_list = new ArrayList<OFMatchField>();
		OFMatchField etype = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
		OFMatchField dst_m = new OFMatchField(OFOXMFieldType.ETH_DST, Ethernet.toByteArray(hst.getMACAddress()));
		OFMatchField src_m = new OFMatchField(OFOXMFieldType.ETH_SRC, Ethernet.toByteArray(hst.getMACAddress()));
		
		field_list.add(etype);
		field_list.add(dst_m);
		field_list.add(src_m);
		om.setMatchFields(field_list);
		
		for(IOFSwitch shc : getSwitches().values()) {
			SwitchCommands.removeRules(shc, table, om);
		}
	}
	

	public void del_flow_tabs() {

		for(Host hst : getHosts()) {
			del_flow(hst);
			
		}
	}
	/**************************************************************************************/


    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
		
			create_flow_tabs();

		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		

		del_flow(host);
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
	
		del_flow(host);
		create_flow_tabs();
	}
	
    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override		
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		
		del_flow_tabs();
		this.paths = bf_shortest_path();
		create_flow_tabs();

	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		
		del_flow_tabs();
		this.paths = bf_shortest_path();
		create_flow_tabs();

		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		

		this.paths = bf_shortest_path();
		create_flow_tabs();

	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
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
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(InterfaceShortestPathSwitching.class);
		return services; 
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>, 
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(InterfaceShortestPathSwitching.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}
}
