package net.floodlightcontroller.unipi.maliciousflowsquarantine.api.resources;

import java.io.IOException;

import org.restlet.resource.Delete;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.floodlightcontroller.unipi.maliciousflowsquarantine.api.IMaliciousFlowsQuarantineREST;

public class UnmarkFlow extends ServerResource {
    @Delete("json")
    public String unmarkFlowAndInitiateAction(String fmJson) {
        // Get the operation from the request attributes
        String method = (String) getRequestAttributes().get("method");

        // Validate the operation
        if (method == null || (!"flush".equalsIgnoreCase(method) && !"clear".equalsIgnoreCase(method))) {
            return JsonResponseUtil.errorResponse("Invalid operation! It must be 'flush' or 'clear'.");
        }

        
        // Check if the payload is provided
        if (fmJson == null || fmJson.isEmpty()) {
            return JsonResponseUtil.errorResponse("No attributes provided.");
        }

        // Parse the JSON input
        ObjectMapper mapper = new ObjectMapper();
        try {
            JsonNode root = mapper.readTree(fmJson);
            
            // Get the fields clientIP and serverIP
            String clientIP = root.get("clientIP").asText();
            String serverIP = root.get("serverIP").asText();

            // Validate the clientIP and serverIP
            if (clientIP == null || clientIP.isEmpty()) {
                return JsonResponseUtil.errorResponse("Invalid clientIP: cannot be null or empty.");
            }
            if (serverIP == null || serverIP.isEmpty()) {
                return JsonResponseUtil.errorResponse("Invalid serverIP: cannot be null or empty.");
            }

            // Get the IMaliciousFlowsQuarantineREST service and call unmarkFlow
            IMaliciousFlowsQuarantineREST mfq = (IMaliciousFlowsQuarantineREST) getContext().getAttributes().get(IMaliciousFlowsQuarantineREST.class.getCanonicalName());
            
            String bufferMessage = mfq.unmarkFlow(clientIP, serverIP, method);
            
            // Return success response with buffer message
            return JsonResponseUtil.successResponse(bufferMessage);
            
        } catch (IOException e) {
            e.printStackTrace();
            return JsonResponseUtil.errorResponse("Error parsing JSON input.");
        }
    }
}