package net.floodlightcontroller.unipi.maliciousflowsquarantine.api.resources;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;


import java.util.HashMap;
import java.util.Map;

public class JsonResponseUtil {
    
    private static final ObjectMapper mapper = new ObjectMapper();

    // Success Response
    public static String successResponse(String message, String uuid) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", message);
        response.put("uuid", uuid);
        return toJson(response);
    }
    
    public static String successResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", message);
        return toJson(response);
    }
    public static String successResponse(String message,int bufferedPackets) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", message);
        response.put("bufferedPackets", bufferedPackets);
        return toJson(response);
    }

    // Error Response
    public static String errorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", message);
        response.put("uuid", null);
        return toJson(response);
    }

    // Convert Map to JSON String
    private static String toJson(Map<String, Object> map) {
        try {
            return mapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return "{\"status\":\"error\",\"message\":\"JSON serialization failed\",\"uuid\":null}";
        }
    }

}
