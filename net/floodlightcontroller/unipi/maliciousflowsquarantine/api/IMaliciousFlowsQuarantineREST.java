package net.floodlightcontroller.unipi.maliciousflowsquarantine.api;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IMaliciousFlowsQuarantineREST extends IFloodlightService {
    
    public int retrieveTotalBufferedPackets(String id);

    public String markFlow(String clientIP, String serverIP, int bufferSize);

    public String unmarkFlow(String clientIP, String serverIP, String mode);

}