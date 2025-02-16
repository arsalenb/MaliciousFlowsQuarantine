package net.floodlightcontroller.unipi.maliciousflowsquarantine;


import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;

import org.projectfloodlight.openflow.protocol.OFMessage;

public class FlowBuffer {
    private Queue<OFMessage> buffer;
    private int maxSize;

    public FlowBuffer(int size) {
        this.maxSize = size;
        this.buffer = new ArrayDeque<>(size);
    }

    // Add a packet to the buffer
    public void addPacket(OFMessage packet) {
        if (buffer.size() >= maxSize) {
            buffer.poll(); // Remove oldest packet if full
        }
        buffer.offer(packet);
    }

    // Flush all packets (send them out)
    public List<OFMessage> flushBuffer() {
        List<OFMessage> flushedPackets = new ArrayList<>(buffer);
        buffer.clear();
        return flushedPackets;
    }

    // Clear the buffer (drop all packets)
    public void clearBuffer() {
        buffer.clear();
    }

    // Get the number of stored packets
    public int getBufferSize() {
        return buffer.size();
    }
    
    //  Change buffer size dynamically
    public void changeBufferSize(int newSize) {
        this.maxSize = newSize;
        while (buffer.size() > newSize) {
            buffer.poll(); // Remove oldest packets if necessary
        }
    }
}