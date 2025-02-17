package net.floodlightcontroller.unipi.maliciousflowsquarantine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.types.DatapathId;

public class FlowsManager {
    // Store quarantine buffers per flow (UUID → Buffer)
    private final Map<String, PacketsBuffer> quarantineBuffers = new HashMap<>();

    // Mapping from UUID → flow identifier (e.g., "clientIP_serverIP")
    private final Map<String, String> flowMappings = new HashMap<>();
    private final int DEFAULT_BUFFER_SIZE = 50;

    private final Map<String, Map<DatapathId, OFMessage>> flowRules = new HashMap<>();

    // Mark a flow as malicious and prepare storage for flow rules
    public String markFlow(String clientIp, String serverIp) {
        String flowId = clientIp + "_" + serverIp;
        String uuid = UUID.randomUUID().toString();
        quarantineBuffers.put(uuid, new PacketsBuffer(DEFAULT_BUFFER_SIZE));
        flowMappings.put(uuid, flowId);
        flowRules.put(uuid, new HashMap<>()); // Use DatapathId as key
        return uuid;
    }

    // Store the flow rule for a switch (DatapathId)
    public void addFlowRule(String uuid, DatapathId switchId, OFMessage rule) {
        Map<DatapathId, OFMessage> rulesForFlow = flowRules.get(uuid);
        if (rulesForFlow != null) {
            rulesForFlow.put(switchId, rule);
        }
    }

    // Retrieve all flow rules for a flow
    public Map<DatapathId, OFMessage> getFlowRules(String uuid) {
        return flowRules.get(uuid);
    }

    // Buffer a packet using the UUID (
    public void bufferPacket(String uuid, OFMessage packet) {
        PacketsBuffer buffer = quarantineBuffers.get(uuid);
        if (buffer != null) {
            buffer.addPacket(packet);
        }
    }

    // Unmark a flow and retrieve its rules for deletion
    public List<OFMessage> unmarkAndFlush(String uuid) {
        quarantineBuffers.remove(uuid);
        flowMappings.remove(uuid);
        Map<DatapathId, OFMessage> rulesForFlow = flowRules.remove(uuid);
        return (rulesForFlow != null) ? new ArrayList<>(rulesForFlow.values()) : new ArrayList<>();
    }

    // Unmark a flow and delete all associated rules
    public void unmarkAndClear(String uuid) {
        quarantineBuffers.remove(uuid);
        flowMappings.remove(uuid);
        flowRules.remove(uuid);
    }

    // Retrieve the buffer size for a flow
    public int getBufferSize(String uuid) {
        PacketsBuffer buffer = quarantineBuffers.get(uuid);
        return (buffer != null) ? buffer.getBufferSize() : 0;
    }
}
