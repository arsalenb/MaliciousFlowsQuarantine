package net.floodlightcontroller.unipi.maliciousflowsquarantine.api.resources;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

import net.floodlightcontroller.unipi.maliciousflowsquarantine.api.IMaliciousFlowsQuarantineREST;

public class BufferSize extends ServerResource {

    
    @Get("json")
    public String totalBufferedPackets() {
        String flowId = (String) getRequestAttributes().get("id");
        // check the parameters
        if (flowId == null) {
            return JsonResponseUtil.errorResponse("Flow ID not provided.");
        }
        
        IMaliciousFlowsQuarantineREST mfq = (IMaliciousFlowsQuarantineREST) getContext().getAttributes().get(IMaliciousFlowsQuarantineREST.class.getCanonicalName());
        
        int bufferedPackets = mfq.retrieveTotalBufferedPackets(flowId);

        // If no packets, return an appropriate response
        if (bufferedPackets < 0) {
            return JsonResponseUtil.errorResponse("Failed to retrieve buffered packets.");
        }
        
        // Return success response with buffer size
        return JsonResponseUtil.successResponse("Flow exists", bufferedPackets);
    }
}