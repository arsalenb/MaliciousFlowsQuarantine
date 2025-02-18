package net.floodlightcontroller.unipi.maliciousflowsquarantine;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.util.FlowModUtils;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;

public class FlowUtils {
	
	// Rule timeouts
	private final static short IDLE_TIMEOUT = 60;
	private final static short HARD_TIMEOUT = 120; 

	// Logger for the class
    private static final Logger log = LoggerFactory.getLogger(MaliciousFlowsQuarantine.class);
    
    // Install flow rule to redirect to s4/controller
    public static void installFlow(IOFSwitch sw, MaliciousFlow flow, OFPort nextHopPort, OFPacketIn packetIn) {
        OFFactory factory = sw.getOFFactory();

        // Create Match for the flow
        Match match = factory.buildMatch()
                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.IPV4_DST, IPv4Address.of(flow.getServerIp()))
                .setExact(MatchField.IPV4_SRC, IPv4Address.of(flow.getClientIp()))
                .build();

        // Create Flow-Mod message
        OFFlowMod.Builder flowMod = factory.buildFlowAdd()
                .setIdleTimeout(IDLE_TIMEOUT)
                .setHardTimeout(HARD_TIMEOUT)
                .setMatch(match)
                .setPriority(FlowModUtils.PRIORITY_MAX)
                .setFlags(Collections.singleton(OFFlowModFlags.SEND_FLOW_REM)); // Send FLOW_REMOVED on expiry

        // Set output action to nextHopPort
        flowMod.setActions(Arrays.asList(factory.actions().buildOutput().setPort(nextHopPort).build()));

        // Write the Flow-Mod rule to the switch
        sw.write(flowMod.build());

        // If the buffer ID is valid, instruct the switch to forward the buffered packet
        if (packetIn != null) {
            // Extract buffer ID from the PACKET_IN message
            OFBufferId bufferId = packetIn.getBufferId();
            boolean hasBuffer = !bufferId.equals(OFBufferId.NO_BUFFER);

            if (hasBuffer) {
                sendBufferedPacket(sw, bufferId, nextHopPort);
            } else {
                sendUnbufferedPacket(sw, packetIn, nextHopPort);
            }
        }
        
        log.info("Flow rule applied on switch with ID: {}", sw.getId());

    }

    //  Sends a buffered packet if a buffer ID is available
    private static void sendBufferedPacket(IOFSwitch sw, OFBufferId bufferId, OFPort outPort) {
        OFFactory factory = sw.getOFFactory();
        
        OFPacketOut packetOut = factory.buildPacketOut()
                .setBufferId(bufferId) // Use the switch’s buffer
                .setActions(Arrays.asList(factory.actions().buildOutput().setPort(outPort).build()))
                .build();

        sw.write(packetOut);
    }

    //  Sends the full packet manually if NO_BUFFER is set
    public static void sendUnbufferedPacket(IOFSwitch sw, OFPacketIn packetIn, OFPort outPort) {
        OFFactory factory = sw.getOFFactory();

        OFPacketOut.Builder packetOut = factory.buildPacketOut()
                .setBufferId(OFBufferId.NO_BUFFER) // No buffer, send manually
                .setData(packetIn.getData()) // Include the full packet data
                .setActions(Arrays.asList(factory.actions().buildOutput().setPort(outPort).build()));

        sw.write(packetOut.build());
    }


    //  Delete flow rules
    public static void deleteFlowRule(IOFSwitch sw, MaliciousFlow flow) {
        OFFactory factory = sw.getOFFactory();

        Match match = factory.buildMatch()
                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.IPV4_SRC, IPv4Address.of(flow.getClientIp()))
                .setExact(MatchField.IPV4_DST, IPv4Address.of(flow.getServerIp()))
                .build();

        OFFlowMod.Builder deleteFlow = factory.buildFlowDelete()
                .setTableId(TableId.of(0))
                .setMatch(match);

        sw.write(deleteFlow.build());
        log.info("Deleted flow applied on switch with ID: {}", sw.getId());

    }
}