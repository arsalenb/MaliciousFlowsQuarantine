# 583II - Advanced Network Architectures and Wireless Systems: Malicious Flows Quarantine

This project was developed for the **Advanced Network Architectures and Wireless Systems** course. The goal was to design and implement a **quarantine mechanism** to handle malicious network flows in Software-Defined Networking (SDN) environments.

Marked malicious flows are rerouted to a **quarantine switch**, which forwards their packets to the controller for buffering. The controller then decides whether to **drop** the packets or **flush** them to their intended destinations, enabling fine-grained traffic control and security enforcement.

---

## Project Description

The project extends the **Floodlight controller** with a custom module that provides:  

- **Flow quarantine logic** – intercepts suspicious flows and redirects them to the quarantine switch.  
- **Buffering and control** – quarantined traffic is temporarily stored until a decision is made.  
- **RESTful API** – allows administrators to manage and inspect quarantined flows (add, release, or drop).  

Testing and validation were conducted using **Mininet**, an SDN network emulator. A Mininet topology script is included in the repository root for reproducible experiments.

---

## Project Structure

- **Floodlight module** – Implements the quarantine mechanism and integrates with the controller.  
- **RESTful API** – Exposes endpoints for managing quarantined flows.  
- **Mininet topology script** – Defines the test network used for emulation and validation.  

---

## Execution

### 1. Setup Floodlight
Clone and build Floodlight with the custom module:

```bash
git clone https://github.com/floodlight/floodlight.git
```

Run Floodlight:

```bash
java -jar target/floodlight.jar
```

### 2. Run Mininet Topology

From the project root:

```bash
sudo python mininet-topology.py
cd floodlight
ant
```
### 3. Interact with the REST API

Example – list quarantined flows:

```bash
curl http://localhost:8080/wm/quarantine/flows/json
```
