package net.floodlightcontroller.unipi.maliciousflowsquarantine.api.resources;

import java.io.IOException;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.floodlightcontroller.unipi.maliciousflowsquarantine.api.IMaliciousFlowsQuarantineREST;

public class MarkFlow extends ServerResource {
    
    @Post("json")
    public String markFlow(String fmJson) {
        // Check if the payload is provided
        if (fmJson == null) {
            return JsonResponseUtil.errorResponse("No attributes provided");
        }

        // Parse the JSON input
        ObjectMapper mapper = new ObjectMapper();
        try {
            JsonNode root = mapper.readTree(fmJson);
            
            // Get the fields clientIP, serverIP, and bufferSize
            String clientIP = root.get("clientIP").asText();
            String serverIP = root.get("serverIP").asText();
            int bufferSize = Integer.parseInt(root.get("bufferSize").asText());

            // Validation for clientIP, serverIP and bufferSize
            if (clientIP == null || clientIP.isEmpty()) {
                return JsonResponseUtil.errorResponse("Invalid clientIP");
            }
            if (serverIP == null || serverIP.isEmpty()) {
                return JsonResponseUtil.errorResponse("Invalid serverIP");
            }
            if (bufferSize <= 0) {
                return JsonResponseUtil.errorResponse("Invalid buffer size");
            }
            // Get the IMaliciousFlowsQuarantineREST service and call markFlow
            IMaliciousFlowsQuarantineREST mfq = (IMaliciousFlowsQuarantineREST) getContext().getAttributes().get(IMaliciousFlowsQuarantineREST.class.getCanonicalName());
            if (mfq == null) {
                return JsonResponseUtil.errorResponse("Malicious flow service unavailable");
            }

            // Mark the flow and get the UUID
            String uuid = mfq.markFlow(clientIP, serverIP, bufferSize);

            if (uuid != null && !uuid.isEmpty()) {
                return JsonResponseUtil.successResponse("Flow marked successfully", uuid);
            } else {
                return JsonResponseUtil.errorResponse("Flow could not be created");
            }

        } catch (IOException e) {
            e.printStackTrace();
            return JsonResponseUtil.errorResponse("Error parsing JSON input");
        } catch (NumberFormatException e) {
            e.printStackTrace();
            return JsonResponseUtil.errorResponse("Invalid buffer size format");
        }
    }
}
