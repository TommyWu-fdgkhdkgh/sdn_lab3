/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.testapp;

import com.google.common.collect.ImmutableSet;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.util.KryoNamespace;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
//import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.MultiValuedTimestamp;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.WallClockTimestamp;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.onlab.util.Tools.groupedThreads;
import static org.slf4j.LoggerFactory.getLogger;


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
@Service(value = AppComponent.class)
public class AppComponent {

    private static final int DEFAULT_TIMEOUT = 100000;
    private static final int DEFAULT_PRIORITY = 100000;

    //private final Logger log = LoggerFactory.getLogger(getClass());
    private final Logger log = getLogger(getClass());


    //在使用onos的各種服務前，要先註冊一個唯一的id號
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    //有註冊這個，才能監聽封包
    //to receive packet-in events that we'll respond to
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService cfgService;

    // our application-specific event handler
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    // mac address table
    private Map<DeviceId, Map<MacAddress, PortNumber>> mac_to_port = new HashMap<DeviceId, Map<MacAddress, PortNumber>>();

    //代表該應用程式的id
    private ApplicationId appId;

    @Property(name = "packetOutOnly", boolValue = false,
            label = "Enable packet-out only forwarding; default is false")
    private boolean packetOutOnly = false;

    @Property(name = "packetOutOfppTable", boolValue = false,
            label = "Enable first packet forwarding using OFPP_TABLE port " +
                    "instead of PacketOut with actual port; default is false")
    private boolean packetOutOfppTable = false;

    //常量的設置方式，此處是流表過期時間設定
    @Property(name = "flowTimeout", intValue = DEFAULT_TIMEOUT,
            label = "Configure Flow Timeout for installed flow rules; " +
                    "default is 10 sec")
    private int flowTimeout = DEFAULT_TIMEOUT;

    @Property(name = "flowPriority", intValue = DEFAULT_PRIORITY,
            label = "Configure Flow Priority for installed flow rules; " +
                    "default is 10")
    //private int flowPriority = DEFAULT_PRIORITY;
    private int flowPriority = 40001;

    @Property(name = "ipv6Forwarding", boolValue = false,
            label = "Enable IPv6 forwarding; default is false")
    private boolean ipv6Forwarding = false;

    @Property(name = "matchDstMacOnly", boolValue = false,
            label = "Enable matching Dst Mac Only; default is false")
    private boolean matchDstMacOnly = false;

    @Property(name = "matchVlanId", boolValue = false,
            label = "Enable matching Vlan ID; default is false")
    private boolean matchVlanId = false;

    @Property(name = "matchIpv4Address", boolValue = true,
            label = "Enable matching IPv4 Addresses; default is true")
    private boolean matchIpv4Address = true;

    @Property(name = "matchIpv4Dscp", boolValue = false,
            label = "Enable matching IPv4 DSCP and ECN; default is false")
    private boolean matchIpv4Dscp = false;

    @Property(name = "matchIpv6Address", boolValue = false,
            label = "Enable matching IPv6 Addresses; default is false")
    private boolean matchIpv6Address = false;

    @Property(name = "matchIpv6FlowLabel", boolValue = false,
            label = "Enable matching IPv6 FlowLabel; default is false")
    private boolean matchIpv6FlowLabel = false;

    @Property(name = "matchTcpUdpPorts", boolValue = true,
            label = "Enable matching TCP/UDP ports; default is true")
    private boolean matchTcpUdpPorts = true;

    @Property(name = "matchIcmpFields", boolValue = true,
            label = "Enable matching ICMPv4 and ICMPv6 fields; " +
                    "default is true")
    private boolean matchIcmpFields = true;


    @Property(name = "ignoreIPv4Multicast", boolValue = false,
            label = "Ignore (do not forward) IPv4 multicast packets; default is false")
    private boolean ignoreIpv4McastPackets = false;

    @Property(name = "recordMetrics", boolValue = false,
            label = "Enable record metrics for reactive forwarding")
    private boolean recordMetrics = false;



    @Activate
    protected void activate() {
    //好像要在pom.xml裡面做設定，才能使用ComponentContext

        appId = coreService.registerApplication("nctu.winlab.testapp");
  
        packetService.addProcessor(processor, PacketProcessor.director(2));

        requestIntercepts();

        //nctu.winlab.testapp
        log.info("Started 222");
	log.info("Hello!");
    }

    @Deactivate
    protected void deactivate() {
     
        packetService.removeProcessor(processor);
        processor = null;
 
        withdrawIntercepts();

        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
    }

    /**
     * Request packet in via packet service.
     *   
     * 大概是在擷取的時候，指定想要擷取哪些封包吧
     */
    private void requestIntercepts() {
        //Abstraction of a slice of network traffic.
        //Builder of traffic selector entities.
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);


        selector.matchEthType(Ethernet.TYPE_IPV6);
        if (ipv6Forwarding) {
            packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        } else {
            packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        }
    }

    /**
     * Cancel request for packet in via packet service.
     * 反正就是做跟requestIntercepts相反的事情
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {


            log.info("-------------start to process--------------");

            if (context.isHandled()) {
                log.info("is handled!");
                log.info("-------------end of process--------------");
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            // 是lldp, bddp就drop掉
            if (isControlPacket(ethPkt)) {
                return;
            }


            // Skip IPv6 multicast packet when IPv6 forward is disabled.
            if (!ipv6Forwarding && isIpv6Multicast(ethPkt)) {
                return;
            }

            //HostId : Immutable representation of a host identity.
            //HostId.hostId : Creates a device id using the supplied MAC and default VLAN.
            HostId id = HostId.hostId(ethPkt.getDestinationMAC());


            // Do not process LLDP MAC address in any way.
            if (id.mac().isLldp()) {
                return;
            }

            // Do not process IPv4 multicast packets, let mfwd handle them
            if (ignoreIpv4McastPackets && ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (id.mac().isMulticast()) {
                    return;
                }
            }



            //拿source mac
            MacAddress srcMAC = ethPkt.getSourceMAC();
            //拿source 的port
            PortNumber in_port= context.inPacket().receivedFrom().port();

            //拿destination mac
            MacAddress dstMAC = ethPkt.getDestinationMAC();
            //拿switch deviceId
            DeviceId   sw     = context.inPacket().receivedFrom().deviceId(); 
          
            //要forwarding的port
            PortNumber out_port;

            /*
                mac_to_port[sw][srcMAC]=in_port;
                if dstMAC in mac_to_port[sw]:
                    output_port = mac_to_port[sw][dstMAC]
                else
                    output_port = flood

                if output_port!=flood:
                    flow_mod
                else
                    flood
            */ 
           
            //mac_to_port[sw][srcMAC]=in_port;
            int listall=0;
            if(mac_to_port.containsKey(sw)){
                Map tempMap = mac_to_port.get(sw);
                if(!tempMap.containsKey(srcMAC)){
                    log.info("learning!");
                    tempMap.put(srcMAC,in_port);
                    listall=1; 
                }
            }else{
                mac_to_port.put(sw,new HashMap<MacAddress, PortNumber>());
                Map tempMap = mac_to_port.get(sw);
                tempMap.put(srcMAC, in_port);
                log.info("learning!");
                listall=1;
            }
           
            /* 
            if(listall==1){
                log.info("start to iterate mac address table");
                Iterator it = mac_to_port.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry pair = (Map.Entry)it.next();
                    Map<MacAddress, PortNumber> tempMap = (Map<MacAddress, PortNumber>)pair.getValue();
                    Iterator itt = tempMap.entrySet().iterator();
                    log.info("switch:{}",pair.getKey());
                    while(itt.hasNext()){
                        Map.Entry pp = (Map.Entry)itt.next();
                        log.info(pp.getKey() + " = " + pp.getValue());                                       
                        itt.remove();
                    }
                    //System.out.println(pair.getKey() + " = " + pair.getValue());
                    it.remove(); // avoids a ConcurrentModificationException
                }
            }*/

            //if dstMAC in mac_to_port[sw]
            int floodflag = 0;
            Map<MacAddress, PortNumber> tempMap = mac_to_port.get(sw);
            if(tempMap.containsKey(dstMAC)){
                //out_port=tempMap.get(dstMAC);
                floodflag = 0;
            }else{
                floodflag = 1;
            }

            if(floodflag==0){
              out_port=tempMap.get(dstMAC);
              installRule(context, out_port);
            }else{
              flood(context);
            }

            //1.把source mac紀錄在mac_to_port[switch][mac]=in_port
            //2.看dst    mac有沒有在mac_to_port表裡
            //    有的話，flow_add
            //    沒有的話，flood

            log.info("process! src:{} dst:{}", srcMAC.toString(), dstMAC.toString());
            log.info("context.inPacket().receivedFrom().deviceId():{}",context.inPacket().receivedFrom().deviceId());
            log.info("-------------end of process--------------");
        }
    }

    // Sends a packet out the specified port.
    // 送出封包到指定的port，或是flood
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
        log.info("packetOut! {}", portNumber.toString());
    }

    //flood
    private void flood(PacketContext context) {
        packetOut(context, PortNumber.FLOOD);
        log.info("flood!");
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber) {

        //
        // We don't support (yet) buffer IDs in the Flow Service so
        // packet out first.
        //
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        if (matchDstMacOnly) {
            log.info("matchDstMacOnly");
            selectorBuilder.matchEthDst(inPkt.getDestinationMAC());
        } else {
            log.info("not matchDstMacOnly");

            selectorBuilder.matchInPort(context.inPacket().receivedFrom().port())
                    .matchEthSrc(inPkt.getSourceMAC())
                    .matchEthDst(inPkt.getDestinationMAC());

            // If configured Match Vlan ID
            /*if (matchVlanId && inPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                selectorBuilder.matchVlanId(VlanId.vlanId(inPkt.getVlanID()));
            }*/

            //
            // If configured and EtherType is IPv4 - Match IPv4 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv4Address && inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                log.info("matchIpv4Address");
                IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
                byte ipv4Protocol = ipv4Packet.getProtocol();

                log.info("ipv4Protocol:{}",ipv4Protocol);


                Ip4Prefix matchIp4SrcPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                          Ip4Prefix.MAX_MASK_LENGTH);
                Ip4Prefix matchIp4DstPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                          Ip4Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPSrc(matchIp4SrcPrefix)
                        .matchIPDst(matchIp4DstPrefix);

                if (matchIpv4Dscp) {
                    log.info("matchIpv4Dscp");
                    byte dscp = ipv4Packet.getDscp();
                    byte ecn = ipv4Packet.getEcn();
                    selectorBuilder.matchIPDscp(dscp).matchIPEcn(ecn);
                }

                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_TCP) {
                    log.info("matchTcpUdpPorts + TCP");
                    TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_UDP) {
                    log.info("matchTcpUdpPorts + UDP");
                    UDP udpPacket = (UDP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                            .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
                if (matchIcmpFields && ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                    log.info("matchIcmpFields + ICMP");
                    ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchIcmpType(icmpPacket.getIcmpType())
                            .matchIcmpCode(icmpPacket.getIcmpCode());
                }
            }
                    //
            // If configured and EtherType is IPv6 - Match IPv6 and
            // TCP/UDP/ICMP fields
            //
            /*
            if (matchIpv6Address && inPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Packet = (IPv6) inPkt.getPayload();
                byte ipv6NextHeader = ipv6Packet.getNextHeader();
                Ip6Prefix matchIp6SrcPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getSourceAddress(),
                                          Ip6Prefix.MAX_MASK_LENGTH);
                Ip6Prefix matchIp6DstPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getDestinationAddress(),
                                          Ip6Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV6)
                        .matchIPv6Src(matchIp6SrcPrefix)
                        .matchIPv6Dst(matchIp6DstPrefix);

                if (matchIpv6FlowLabel) {
                    selectorBuilder.matchIPv6FlowLabel(ipv6Packet.getFlowLabel());
                }

                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                            .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
                if (matchIcmpFields && ipv6NextHeader == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchIcmpv6Type(icmp6Packet.getIcmpType())
                            .matchIcmpv6Code(icmp6Packet.getIcmpCode());
                }
            }*/
        }

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

 
        //ForwardingObjective : 製造flow mod封包
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .add();

        //flowObjectiveService : Service for programming data plane flow rules in manner independent of specific device table pipeline configuration.
        //flowObjectiveService.forward : Installs the forwarding rules onto the specified device.
        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                                     forwardingObjective);


        //這邊應該要加個packetOut，不然一開始的封包都會被丟掉
        //感覺就像是ICMP被吃掉，然後只有丟出flow_mod一樣
        packetOut(context, PortNumber.TABLE);

 
        log.info("install rules!");

    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }


    // 判斷是不是ipv6 multicast packet
    // Indicated whether this is an IPv6 multicast packet.
    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }


}
