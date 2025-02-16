package net.floodlightcontroller.unipi.maliciousflowsquarantine;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;

public class MaliciousFlowsQuarantine implements IOFMessageListener, IFloodlightModule {
    
    protected IFloodlightProviderService floodlightProvider; // Reference to the provider

    // Logger for the class
    private static final Logger log = LoggerFactory.getLogger(MaliciousFlowsQuarantine.class);

    // Fixed DPID of Quarantine Switch
    private final static String quarantineSwitchDpid = "00:00:00:00:00:00:00:04";
    
    // Rule timeouts
    private final static short IDLE_TIMEOUT = 60;
    private final static short HARD_TIMEOUT = 120; 

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
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        log.info("MaliciousFlowsQuarantine module initialized.");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        log.info("MaliciousFlowsQuarantine module started and listening for PACKET_IN messages.");
    }

    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
            FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        // Get the source MAC address
        String sourceMAC = eth.getSourceMACAddress().toString();

        // Log the event
        log.info("MAC Address: {} seen on switch: {}", sourceMAC, sw.getId());

        // Let other modules process the packet
        return Command.CONTINUE;
    }
}