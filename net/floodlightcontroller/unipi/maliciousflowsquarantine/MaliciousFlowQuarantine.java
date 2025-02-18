package net.floodlightcontroller.unipi.maliciousflowsquarantine;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Path;
import net.floodlightcontroller.unipi.maliciousflowsquarantine.FlowUtils;
import net.floodlightcontroller.unipi.maliciousflowsquarantine.api.IMaliciousFlowsQuarantineREST;
import net.floodlightcontroller.unipi.maliciousflowsquarantine.api.MaliciousFlowsQuarantineWebRoutable;

public class MaliciousFlowsQuarantine implements IOFMessageListener, IFloodlightModule, IMaliciousFlowsQuarantineREST {
	
    protected IFloodlightProviderService floodlightProvider;
    protected IRestApiService restApiService; 
    protected IOFSwitchService switchService;  
    protected IRoutingService routingService; // Use IRoutingService

    
	// Logger for the class
    public static final Logger log = LoggerFactory.getLogger(MaliciousFlowsQuarantine.class);

    // Current marked malicious flows
    private List<MaliciousFlow> activeFlows= new ArrayList<>();;
    
	// Fixed DPID of Quarantine Switch
    private final static DatapathId quarantineSwitchDpid = DatapathId.of("00:00:00:00:00:00:00:04");

	
	@Override
	public String getName() {
		return MaliciousFlowsQuarantine.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        	    Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IMaliciousFlowsQuarantineREST.class);
	    return l;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = 
	            new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	        
	        m.put(IMaliciousFlowsQuarantineREST.class, this);
	        return m;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<>();
        l.add(IFloodlightProviderService.class);
        l.add(IOFSwitchService.class);
        l.add(IRoutingService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
        restApiService = context.getServiceImpl(IRestApiService.class);
        routingService = context.getServiceImpl(IRoutingService.class);
        log.info("MaliciousFlowsQuarantine module initialized");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
		restApiService.addRestletRoutable(new MaliciousFlowsQuarantineWebRoutable());
        log.info("MaliciousFlowsQuarantine module started and listening for messages.");
    }

    @Override
    public String markFlow(String clientIp, String serverIp,int bufferSize) {
        // Check if flow already exists
        for (MaliciousFlow flow : activeFlows) {
            if (flow.getClientIp().equals(clientIp) && flow.getServerIp().equals(serverIp)) {
                // Flow already exists, so we update the buffer size
                flow.changeBufferSize(bufferSize);
                log.info("Flow already marked as malicious. Buffer size updated: {} -> {}", clientIp, serverIp);

                return flow.getUuid(); // Return the existing flow with the updated buffer size
            }
        }

        //  Create and store the new malicious flow
        MaliciousFlow newFlow = new MaliciousFlow(clientIp, serverIp, bufferSize);
        activeFlows.add(newFlow); 

        // Apply redirection rules to all switches
        for (IOFSwitch sw : switchService.getAllSwitchMap().values()) {
            DatapathId switchId = sw.getId();

            if (switchId.equals(quarantineSwitchDpid)) {
                // Quarantine switch (`s4`) → Forward packets to the controller
            	FlowUtils.installFlow(sw, newFlow, OFPort.CONTROLLER, null);
            } else {
                // Regular switch → Find path to `s4` and forward packets
                OFPort nextHopPort = findNextHop(switchId, quarantineSwitchDpid);
                if (nextHopPort != null) {
                	FlowUtils.installFlow(sw, newFlow, nextHopPort, null);
                } else {
                	log.warn("No path to quarantine switch from {}", switchId);            
                }
            }
        }
        return newFlow.getUuid(); // Return the new flow's UUID     
    }

    @Override
    public String unmarkFlow(String clientIp, String serverIp, String method) {
        MaliciousFlow flow = getMaliciousFlow(clientIp, serverIp);
        
        if (flow == null) {
            return "Flow not found.";
        }
        
        
        // Remove the flow from active tracking
        activeFlows.remove(flow);

        //  Delete flow rules from all affected switches
        for (IOFSwitch sw : switchService.getAllSwitchMap().values()) {
            if (sw != null) {
            	FlowUtils.deleteFlowRule(sw, flow);
            }
        }

        // Handle buffer according to the provided method
        String bufferMessage = "";
        if ("flush".equals(method)) {
            bufferMessage = flushBufferToQuarantineSwitch(flow);
        } else {
            flow.clearBuffer();
            bufferMessage = "Buffer cleared.";
        }
  
        
        log.info("Flow unmarked successfully: {} -> {}", clientIp, serverIp);
        
        return bufferMessage;
    }

    @Override
    public int retrieveTotalBufferedPackets(String id) {
        // Retrieve the malicious flow using the UUID
        MaliciousFlow flow = getMaliciousFlow(id);
        
        if (flow == null) {
        	log.error("No malicious flow found for ID: {}", id);
            return -1; // Return -1 if no flow is found
        }

        // Return the total number of buffered packets
        return flow.getBufferSize();
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        // Handle flow expiration messages.
        // FLOW_REMOVED messages are sent by switches when a flow times out.
        if (msg.getType() == OFType.FLOW_REMOVED) {
            OFFlowRemoved flowRemoved = (OFFlowRemoved) msg;
            Match expiredMatch = flowRemoved.getMatch();

            String sourceIP = (expiredMatch.get(MatchField.IPV4_SRC) != null) ? expiredMatch.get(MatchField.IPV4_SRC).toString() : null;
            String destinationIP = (expiredMatch.get(MatchField.IPV4_DST) != null) ? expiredMatch.get(MatchField.IPV4_DST).toString() : null;
            
            if (sourceIP == null || destinationIP == null) {
                return Command.CONTINUE; // Ignore if match fields are missing
            }

            // Retrieve flow from active flows list
            MaliciousFlow flow = getMaliciousFlow(sourceIP, destinationIP);

            // Flow is Marked
            if (flow != null) {
            	 if (sw.getId().equals(quarantineSwitchDpid)) {
                     //  Quarantine switch (`s4`) → Forward packets to the controller
                     FlowUtils.installFlow(sw, flow, OFPort.CONTROLLER, null);
                 } else {
                     // Regular switch → Find path to `s4` and forward packets
                     OFPort nextHopPort = findNextHop(sw.getId(), quarantineSwitchDpid);
                     if (nextHopPort != null) {
                    	 FlowUtils.installFlow(sw, flow, nextHopPort, null);
                         return Command.STOP;
                     } else {
                    	 log.warn("No path to quarantine switch from {}", sw.getId());
                         return Command.CONTINUE;
                     }
                 }
                // Let other modules process this
                return Command.CONTINUE;
            }

        }
            
            // Handle PACKET_IN messages
            if (msg.getType() == OFType.PACKET_IN) {
                OFPacketIn packetIn = (OFPacketIn) msg;

                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
                
                // Check if it's IPv4 traffic
                if (!(eth.getPayload() instanceof IPv4)) {
                    return Command.CONTINUE; // Ignore non-IPv4 packets
                }

                 // Extract client and server ip addresses
                IPv4 ipv4 = (IPv4) eth.getPayload();
                String clientIp = ipv4.getSourceAddress().toString();
                String serverIp = ipv4.getDestinationAddress().toString();
                
                // Retrieve the corresponding flow 
                MaliciousFlow flow = getMaliciousFlow(clientIp, serverIp);

                // Case 1: Packet from quarantine switch (`s4`)
                if (sw.getId().equals(quarantineSwitchDpid)) {
                    if (flow != null) {
                        // Save packet in quarantine buffer
                        flow.addPacketToBuffer(msg);
                        return Command.STOP;
                    } else {
                        return Command.CONTINUE;
                    }
                }
                // Case 2: Packet from a regular switch
                else {
                    if (flow != null) {
                        // The flow is marked malicious. Reapply redirection if lost
                        OFPort nextHopPort = findNextHop(sw.getId(), quarantineSwitchDpid);
                        if (nextHopPort != null) {
                            FlowUtils.installFlow(sw, flow, nextHopPort, packetIn);
                            return Command.STOP;
                        } else {
                        	log.warn("No path to quarantine switch from {}", sw.getId());
                            return Command.CONTINUE;
                        }
                    } else {
                        return Command.CONTINUE; // Normal traffic processing
                    }
                }
            }

        // Continue processing for other messages
        return Command.CONTINUE;
    }

    private String flushBufferToQuarantineSwitch(MaliciousFlow flow) {
        List<OFMessage> bufferedPackets = flow.flushBuffer();
        
        if (bufferedPackets.isEmpty()) {
        	log.info("No packets to flush for flow: {} -> {}", flow.getClientIp(), flow.getServerIp());
            return "No packets to flush.";
        }

        IOFSwitch quarantineSwitch = switchService.getSwitch(quarantineSwitchDpid);
        if (quarantineSwitch == null) {
        	log.error("Quarantine switch (s4) not found!");
            return "Quarantine switch not found.";
        }

        // Find a valid output port
        OFPort outputPort = null;
        for (OFPortDesc port : quarantineSwitch.getPorts()) {
            if (!port.getPortNo().equals(OFPort.LOCAL) && !port.getPortNo().equals(OFPort.CONTROLLER)) {
                outputPort = port.getPortNo();
                break; // Use the first valid port found
            }
        }
        
        if (outputPort == null) {
        	log.error("No output port found for quarantine switch.");
            return "Error: No output port found.";
        }

        for (OFMessage packet : bufferedPackets) {
            OFPacketIn packetIn = (OFPacketIn) packet;
            
            // Extract buffer ID from the PACKET_IN message
            OFBufferId bufferId = packetIn.getBufferId();

            OFFactory factory = quarantineSwitch.getOFFactory();
            OFPacketOut.Builder packetOut = factory.buildPacketOut()
                    .setInPort(OFPort.CONTROLLER)
                    .setActions(Arrays.asList(factory.actions().buildOutput().setPort(outputPort).build()));
                    
            if (bufferId == OFBufferId.NO_BUFFER) {
            	byte[] packetData = packetIn.getData();
                packetOut.setData(packetData);
            } 

            quarantineSwitch.write(packetOut.build());
        }

        log.info("Flushed {} packets to quarantine switch.", bufferedPackets.size());
        return "Packets flushed to quarantine switch.";

    }

    private OFPort findNextHop(DatapathId src, DatapathId dst) {
        // Use the correct method to get the path from Floodlight's routing service
        Path route = routingService.getPath(src, dst); 

        if (route == null || route.getPath().isEmpty()) {
            return null; // No valid path
        }

        // The path consists of NodePortTuple elements
        for (NodePortTuple nodePort : route.getPath()) {
            if (nodePort.getNodeId().equals(src)) {
                return nodePort.getPortId(); // Return the output port on `src`
            }
        }

        return null; // Should not reach here if a valid path exists
    }


    private MaliciousFlow getMaliciousFlow(String clientIp, String serverIp) {
        for (MaliciousFlow flow : activeFlows) {
            if (flow.getClientIp().equals(clientIp) && flow.getServerIp().equals(serverIp)) {
                return flow; // Found a matching flow
            }
        }
        return null; // No flow found
    }

    private MaliciousFlow getMaliciousFlow(String uuid) {
        for (MaliciousFlow flow : activeFlows) {
            if (flow.getUuid().equals(uuid)) {
                return flow;
            }
        }
        return null;
    }
}
