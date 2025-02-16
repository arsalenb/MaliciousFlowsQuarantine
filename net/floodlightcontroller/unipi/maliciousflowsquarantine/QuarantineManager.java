package net.floodlightcontroller.unipi.maliciousflowsquarantine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.projectfloodlight.openflow.protocol.OFMessage;

public class QuarantineManager {
    private final Map<String, FlowBuffer> quarantineBuffers = new HashMap<>();
    private final Map<String, String> flowMappings = new HashMap<>(); // UUID → Flow ID
    private final int DEFAULT_BUFFER_SIZE = 50;

    // Mark a flow as malicious
    public String markFlow(String clientIp, String serverIp) {
        String flowId = clientIp + "_" + serverIp;
        String uuid = UUID.randomUUID().toString();
        quarantineBuffers.put(uuid, new FlowBuffer(DEFAULT_BUFFER_SIZE));
        flowMappings.put(uuid, flowId); // Store mapping
        return uuid;
    }

    // Buffer a packet (using UUID)
    public void bufferPacket(String uuid, OFMessage packet) {
        FlowBuffer buffer = quarantineBuffers.get(uuid);
        if (buffer != null) {
            buffer.addPacket(packet);
        }
    }
    
    // Unmark a flow and flush packets
    public List<OFMessage> unmarkAndFlush(String uuid) {
        FlowBuffer buffer = quarantineBuffers.remove(uuid);
        flowMappings.remove(uuid); // Remove mapping
        return (buffer != null) ? buffer.flushBuffer() : new ArrayList<>();
    }

    // Unmark a flow and clear packets
    public void unmarkAndClear(String uuid) {
        quarantineBuffers.remove(uuid);
        flowMappings.remove(uuid);
    }

    // Get buffer size
    public int getBufferSize(String uuid) {
        FlowBuffer buffer = quarantineBuffers.get(uuid);
        return (buffer != null) ? buffer.getBufferSize() : 0;
    }
}