package net.floodlightcontroller.unipi.maliciousflowsquarantine;

import org.projectfloodlight.openflow.protocol.OFMessage;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.UUID;

public class MaliciousFlow {
    private String clientIp;
    private String serverIp;
    private String uuid;
    
    // Queue for buffering packets with a maximum size
    private Queue<OFMessage> buffer;
    private int maxSize;

    // Constructor for MaliciousFlow
    public MaliciousFlow(String clientIp, String serverIp, int bufferSize) {
        this.clientIp = clientIp;
        this.serverIp = serverIp;
        this.uuid = UUID.randomUUID().toString();
        this.maxSize = bufferSize;
        this.buffer = new ArrayDeque<>(bufferSize);
    }

    public String getUuid() {
        return uuid;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getServerIp() {
        return serverIp;
    }

    public Queue<OFMessage> getBuffer() {
        return buffer;
    }


    // Buffer a packet (add to the queue)
    public void addPacketToBuffer(OFMessage packet) {
        if (buffer.size() >= maxSize) {
            buffer.poll(); // Remove oldest packet if buffer is full
        }
        buffer.offer(packet);
    }
    // Flush all buffered packets
    public List<OFMessage> flushBuffer() {
        List<OFMessage> flushedPackets = new ArrayList<>(buffer);
        buffer.clear();
        return flushedPackets;
    }

    // Clear the buffer (drop all packets)
    public void clearBuffer() {
        buffer.clear();
    }

    // Get the current buffer size (number of stored packets)
    public int getBufferSize() {
        return buffer.size();
    }

    // Dynamically change the buffer size (trim excess packets if necessary)
    public void changeBufferSize(int newSize) {
        this.maxSize = newSize;
        while (buffer.size() > newSize) {
            buffer.poll(); // Remove oldest packets if the buffer size exceeds the new limit
        }
    }
}