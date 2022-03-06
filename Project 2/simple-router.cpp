/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

//define constants
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800
#define ARP_OP_REQUEST 0x0001
#define ARP_OP_REPLY 0x0002

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// Helper functions
  
void 
SimpleRouter::incoming_arp_request(arp_hdr * arp_h, const uint8_t * buf, const size_t size, const Interface* iface) 
{
  std::cerr << "*** Handling incoming ARP request ***\n";

  //check whether target IP is interface IP
  if (arp_h->arp_tip != iface->ip)
    { 
      std::cerr << "* ARP request target IP address does not match interface IP address\n";
      return;
    }
  
  //construct ARP headers
  arp_h->arp_op = htons(ARP_OP_REPLY);
  arp_h->arp_tip = arp_h->arp_sip;
  arp_h->arp_sip = iface->ip;  
  for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
      arp_h->arp_tha[i] = arp_h->arp_sha[i];
      arp_h->arp_sha[i] = iface->addr[i];
    }
  
  unsigned char *arp_to_send;
  arp_to_send = (unsigned char*) arp_h;

  //construct ethernet headers
  ethernet_hdr *eth_h = (ethernet_hdr*)(buf);
  for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
      uint8_t temp = eth_h->ether_dhost[i];
      eth_h->ether_dhost[i] = eth_h->ether_shost[i];
      eth_h->ether_shost[i] = temp;
    }
  unsigned char *eth_to_send = (unsigned char*)eth_h;
  Buffer pkt_to_send(size);
  int index = 0;
  for (unsigned int i = 0; i < sizeof(ethernet_hdr); i++)
    {
      pkt_to_send[index] = eth_to_send[i];
      index++;
    }   
  int arp_len = size - sizeof(ethernet_hdr);
  for (int i = 0; i < arp_len; i++)
    {
      pkt_to_send[index] = arp_to_send[i];
      index++;
    }
  
  //send it
  sendPacket(pkt_to_send, iface->name);
  std::cerr << "* ARP reply sent from interface  " << iface->name << std::endl;
}

void
SimpleRouter::handlePing(ip_hdr * ip_h, icmp_hdr * icmp_h, const uint8_t * buf, const size_t size, const Interface* iface) 
{
  std::cerr << "* Handling echo reply to ping\n";

  int icmp_len = size - sizeof(ethernet_hdr) - ((ip_h->ip_hl) * 4);

  //construct ICMP headers
  icmp_h->icmp_type = 0;
  icmp_h->icmp_sum = cksum(icmp_h, icmp_len);
  unsigned char *icmp_to_send = (unsigned char*) icmp_h;

  //construct IP headers
  uint32_t dest_ip = ip_h->ip_dst;
  ip_h->ip_dst = ip_h->ip_src;
  ip_h->ip_src = dest_ip;
  ip_h->ip_sum = cksum(ip_h, (ip_h->ip_hl*4));
  unsigned char *ip_to_send = (unsigned char*) ip_h;

  //construct ethernet headers
  ethernet_hdr *eth_h = (ethernet_hdr*)(buf);
  for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
      uint8_t temp = eth_h->ether_dhost[i];
      eth_h->ether_dhost[i] = eth_h->ether_shost[i];
      eth_h->ether_shost[i] = temp;
    }
  unsigned char *eth_to_send = (unsigned char*) eth_h;

  //put the headers together into new packet to send
  Buffer pkt_to_send(size);
  int index = 0;
  for (unsigned int i = 0; i < sizeof(ethernet_hdr); i++)
    {
      pkt_to_send[index] = eth_to_send[i];
      index++;
    }   
  for (int i = 0; i < ((ip_h->ip_hl) * 4); i++)
    {
      pkt_to_send[index] = ip_to_send[i];
      index++;
    }
  for (int i = 0; i < icmp_len; i++)
    {
      pkt_to_send[index] = icmp_to_send[i];
      index++;
    }

  //send packet
  sendPacket(pkt_to_send, iface->name);
  std::cerr << "* Echo reply sent out of router interface  " << iface->name << std::endl;
}

//Found a mistake - it was only printing the interface facing the caller, not the interface inputted
void
SimpleRouter::handleTracerouteToRouter(ip_hdr * ip_h, const uint8_t * buf, const Interface* iface)
{
  std::cerr << "* Traceroute: router received IP packet with UDP/TCP payload destined to router -> send 'Port Unreachable' message\n";

  //construct IP headers
  ip_hdr *iphts = new ip_hdr;
  iphts->ip_v = ip_h->ip_v;
  iphts->ip_hl = ip_h->ip_hl;
  iphts->ip_tos = 0;
  iphts->ip_id = ip_h->ip_id;
  iphts->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  std::cerr << "* Length of IP packet to be sent: " << ntohs(iphts->ip_len) << std::endl;
  iphts->ip_off = ip_h->ip_off;
  iphts->ip_ttl = 64;
  iphts->ip_p = 1; //ICMP
  iphts->ip_dst = ip_h->ip_src;
  iphts->ip_src = ip_h->ip_dst;
  //iphts->ip_src = iface->ip; <---- this is wrong; want to swap ip src and dest
  iphts->ip_sum = 0;
  iphts->ip_sum = cksum(iphts, (iphts->ip_hl)*4);

  unsigned char *ip_to_send = (unsigned char *) iphts;
  unsigned char *ip_received = (unsigned char *) ip_h;

  //construct ICMP headers
  icmp_t3_hdr *icmp_t3 = new icmp_t3_hdr;
  icmp_t3->icmp_type = 3;
  icmp_t3->icmp_code = 3;

  //put all 20 bytes of IP headers in ICMP data field
  for (int i = 0; i < 20; i++)
    {
      //icmp_t3->data[i] = ip_to_send[i]; <---- This was the problem with traceroute to router
      icmp_t3->data[i] = ip_received[i];
    }
  
  //put 8 bytes of original data datagram into ICMP data field
  for (int i = 20; i < ICMP_DATA_SIZE; i++)
    {
      icmp_t3->data[i] = ip_received[i];
    }

  int icmp_len = 36;
  icmp_t3->icmp_sum = 0;
  icmp_t3->icmp_sum = cksum(icmp_t3, icmp_len);
  unsigned char *icmp_to_send = (unsigned char*) icmp_t3;

  //construct Ethernet headers
  ethernet_hdr *eth_h = (ethernet_hdr*)(buf);
  for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
      uint8_t temp = eth_h->ether_dhost[i];
      eth_h->ether_dhost[i] = eth_h->ether_shost[i];
      eth_h->ether_shost[i] = temp;
    }
  unsigned char *eth_to_send = (unsigned char*) eth_h;

  //put the headers together into new packet to send
  int size = sizeof(ethernet_hdr) + 56;
  Buffer pkt_to_send(size);
  int index = 0;
  for (unsigned int i = 0; i < sizeof(ethernet_hdr); i++)
    {
      pkt_to_send[index] = eth_to_send[i];
      index++;
    }   
  for (int i = 0; i < ((iphts->ip_hl) * 4); i++)
    {
      pkt_to_send[index] = ip_to_send[i];
      index++;
    }
  for (int i = 0; i < icmp_len; i++)
    {
      pkt_to_send[index] = icmp_to_send[i];
      index++;
    }

  //send packet
  print_hdrs(pkt_to_send);
  sendPacket(pkt_to_send, iface->name);
  std::cerr << "* Sent 'Port Unreachable' message  out of router interface " << iface->name << std::endl;

  //free memory allocated by new
  delete(icmp_t3);
  delete(iphts);
}

void
SimpleRouter::handleZeroTTL(ip_hdr * ip_h, const uint8_t * buf, const Interface* iface) 
{
  std::cerr << "* IP header's TTL field is 0 -> send back 'Time Exceeded' message\n";

  //construct IP headers
  ip_hdr *iphts = new ip_hdr;
  iphts->ip_v = ip_h->ip_v;
  iphts->ip_hl = ip_h->ip_hl;
  iphts->ip_tos = 0;
  iphts->ip_id = ip_h->ip_id;
  iphts->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  std::cerr << "* Length of IP packet to be sent: " << ntohs(iphts->ip_len) << std::endl;
  iphts->ip_off = ip_h->ip_off;
  iphts->ip_ttl = 64;
  iphts->ip_p = 1; //ICMP
  iphts->ip_dst = ip_h->ip_src;
  //iphts->ip_src = ip_h->ip_dst;
  iphts->ip_src = iface->ip;
  iphts->ip_sum = 0;
  iphts->ip_sum = cksum(iphts, (iphts->ip_hl) * 4);

  unsigned char *ip_to_send = (unsigned char *) iphts;
  unsigned char *ip_received = (unsigned char *) ip_h;

  //construct ICMP headers
  icmp_t3_hdr *icmp_t3 = new icmp_t3_hdr;
  icmp_t3->icmp_type = 11;
  icmp_t3->icmp_code = 0;
  //put all 20 bytes of IP header in ICMP data field
  for (int i = 0; i < 20; i++)
    {
      icmp_t3->data[i] = ip_received[i];
    }
  //put 8 bytes (64 bits) of original data datagram in ICMP data field
  for (int i = 20; i < ICMP_DATA_SIZE; i++)
    {
      icmp_t3->data[i] = ip_received[i];
    }

  int icmp_len = 36;
  icmp_t3->icmp_sum = 0;
  icmp_t3->icmp_sum = cksum(icmp_t3, icmp_len);
  unsigned char *icmp_to_send = (unsigned char*) icmp_t3;

  //construct Ethernet headers
  ethernet_hdr *eth_h = (ethernet_hdr*)(buf);
  for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
      uint8_t temp = eth_h->ether_dhost[i];
      eth_h->ether_dhost[i] = eth_h->ether_shost[i];
      eth_h->ether_shost[i] = temp;
    }
  unsigned char *eth_to_send = (unsigned char*) eth_h;

  //put the headers together into new packet to send
  int size = sizeof(ethernet_hdr) + 56;
  Buffer pkt_to_send(size);
  int index = 0;
  for (unsigned int i = 0; i < sizeof(ethernet_hdr); i++)
    {
      pkt_to_send[index] = eth_to_send[i];
      index++;
    }   
  for (int i = 0; i < ((iphts->ip_hl) * 4); i++)
    {
      pkt_to_send[index] = ip_to_send[i];
      index++;
    }
  for (int i = 0; i < icmp_len; i++)
    {
      pkt_to_send[index] = icmp_to_send[i];
      index++;
    }

  //send
  print_hdrs(pkt_to_send);
  sendPacket(pkt_to_send, iface->name);
  std::cerr << "* Sent 'Time Exceeded' packet out of router interface " << iface->name << std::endl;

  //free memory allocated by new 
  delete(icmp_t3);
  delete(iphts);
  
/*
  Old code that didn't work

  int size = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
  struct icmp_t3_hdr icmp_header;
  struct ip_hdr ip_header;
  struct ethernet_hdr eth_header;
  //build ethernet header
  ethernet_hdr * recvd_eth = (ethernet_hdr*)(buf);
  memcpy(eth_header.ether_dhost, recvd_eth->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_header.ether_shost, recvd_eth->ether_dhost, ETHER_ADDR_LEN);
  eth_header.ether_type = recvd_eth->ether_type;
  //build ip header
  ip_header.ip_hl = ip_h->ip_hl;
  ip_header.ip_v = ip_h->ip_v;
  ip_header.ip_tos = ip_h->ip_tos;
  ip_header.ip_len = htons(size - sizeof(ethernet_hdr));
  ip_header.ip_id = ip_h->ip_id;
  ip_header.ip_off = ip_h->ip_off;
  ip_header.ip_ttl = 64;
  ip_header.ip_p = 1; //ICMP protocol
  ip_header.ip_src = iface->ip;
  ip_header.ip_dst = ip_h->ip_src;
  ip_header.ip_sum = cksum(&ip_header, (ip_header.ip_hl)*4);
  //build icmp header
  icmp_header.icmp_type = 11;
  icmp_header.icmp_code = 0;
  //memcpy(icmp_header.data, (buf + sizeof(ethernet_hdr)), ICMP_DATA_SIZE);
  unsigned char * ip_received = (unsigned char *) ip_h;
  //put all 20 bytes of IP header into ICMP data field
  for (int i=0; i < 20; i++) {
    icmp_header.data[i] = ip_received[i];
  }
  //put 8 bytes (64 bits) of original data datagram into ICMP data field
  for (int i=20; i < ICMP_DATA_SIZE; i++) {
    icmp_header.data[i] = ip_received[i];
  }
  icmp_header.icmp_sum = cksum(&icmp_header, 36); //this was a problem with traceroute to server
  Buffer pkt_to_send(size, 0);
  memcpy(&pkt_to_send[0], &eth_header, sizeof(ethernet_hdr));
  memcpy(&pkt_to_send[sizeof(ethernet_hdr)], &ip_header, 20);
  memcpy(&pkt_to_send[sizeof(ethernet_hdr) + 20], &icmp_header, 36);
  std::cerr << "Sending ICMP time exceeded pkt with these headers: " << std::endl;
  print_hdrs(pkt_to_send);
  sendPacket(pkt_to_send, iface->name); 
*/
}

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "\n*** Received packet of size " << packet.size() << " on interface " << inIface << " ***\n";

  const Interface *iface = findIfaceByName(inIface);
  if (iface == nullptr)
    {
      std::cerr << "* Packet's interface is unknown -> ignore\n";
      return;
    }

  std::cerr << getRoutingTable() << std::endl;

  //check header to see if ARP or IP packet
  print_hdrs(packet);
  const uint8_t *buf = packet.data();
  const size_t size = packet.size();
  uint16_t eth_type = ethertype(buf);
  std::cerr << "* Type of packet carried by Ethernet frame: " << eth_type << std::endl;

  //handle ARP packet
  if (eth_type == ETHERTYPE_ARP)
    {
      arp_hdr *arp_h = (arp_hdr*)(buf + sizeof(ethernet_hdr));
      unsigned short op_code = ntohs(arp_h->arp_op);

      //incoming ARP request
      if (op_code == ARP_OP_REQUEST)
        incoming_arp_request(arp_h, buf, size, iface);

      //incoming ARP reply
      else if (op_code == ARP_OP_REPLY)
        {
          std::cerr << "*** Handling incoming ARP reply ***\n";
          Buffer mac_Buffer(ETHER_ADDR_LEN, 0);
          memcpy(&mac_Buffer[0], arp_h->arp_sha, ETHER_ADDR_LEN);
          m_arp.insertArpEntry(mac_Buffer, arp_h->arp_sip);
          m_arp.send_pending_packets(*arp_h, arp_h->arp_sip);
          std::cerr << "* ARP reply processed\n";
        }

      //neither
      else
        std::cerr << "* Neither ARP request nor reply\n";
    }

  //handle IP packet
  else if (eth_type == ETHERTYPE_IP)
    {
      std::cerr << "*** Handling IP packet ***\n";
      ip_hdr *ip_h = (ip_hdr*)(buf + sizeof(ethernet_hdr));

      //check validity of IP packet
      uint16_t recvd_checksum = ip_h->ip_sum;
      ip_h->ip_sum = 0;
      uint16_t calcd_checksum = cksum(ip_h, (ip_h->ip_hl)*4);

      //IP headers don't match -> invalid so ignore packet
      if (calcd_checksum != recvd_checksum)
        { 
          std::cerr << "* IP header checksums don't match -> ignore packet\n"
                    << "* IP packet's checksum: " << recvd_checksum << std::endl
                    << "* Calculated checksum: " << calcd_checksum << std::endl;
          return;
        }
      std::cerr << "* Checksums are equal\n";

      //check packet length
      uint16_t pkt_len = ntohs(ip_h->ip_len);
      if (pkt_len < 20)
        {
          std::cerr << "* Invalid IP packet of length " << pkt_len << std::endl;
          return;
        }
      std::cerr << "* Packet length: " << pkt_len << std::endl;

      //extract destination IP address
      uint32_t dest_ip = ip_h->ip_dst;
      std::cerr << "* Destination IP address: " << ipToString(dest_ip) << std::endl;

      //if destination interface is one of the router's interfaces 
      if (auto dest_iface = findIfaceByIp(dest_ip))
        {
          std::cerr << "* Router interface: " << ipToString(dest_iface->ip) << std::endl;

          //handle ICMP packet
          //if packet does not contain ICMP payload -> discard + send 'Port Unreachable' message
          if (ip_h->ip_p == 1)
            { 
              icmp_hdr *icmp_h = (icmp_hdr*)(buf + sizeof(ethernet_hdr) + (ip_h->ip_hl) * 4);

              //check validity of ICMP packet
              uint16_t icmp_recvd_cksum = icmp_h->icmp_sum;
              icmp_h->icmp_sum = 0;
              uint16_t icmp_calcd_cksum;
              int icmp_len = packet.size() - sizeof(ethernet_hdr) - ((ip_h->ip_hl) * 4);
              icmp_calcd_cksum = cksum(icmp_h, icmp_len);

              //checksums are not equal
              if (icmp_recvd_cksum != icmp_calcd_cksum)
                {
                  std::cerr << "* ICMP checksums don't match -> ignore\n"
                            << "* ICMP checksum:  " << icmp_recvd_cksum << std::endl
                            << "* Calculated checksum: " << icmp_calcd_cksum << std::endl;
                  return;
                }
              std::cerr << "* ICMP checksums are equal\n";

              //Only need to handle ICMP packet of type 8 (echo request) here
              if (icmp_h->icmp_type == 8) 
                handlePing(ip_h, icmp_h, buf, size, iface);
            }

          //handle UDP or TCP packet
          else if (ip_h->ip_p == 17 || ip_h->ip_p == 6) 
            handleTracerouteToRouter(ip_h, buf, iface);
        }

      //forward IP packet
      else
        {
          std::cerr << "* Forwarding packet\n";
          RoutingTableEntry rt_entry = m_routingTable.lookup(dest_ip);
          std::cerr << "* Matching routing table entry found: \n" << rt_entry << std::endl;

          //update TTL
          ip_h->ip_ttl -= 1;
          if (ip_h->ip_ttl == 0)
            {
              handleZeroTTL(ip_h, buf, iface);
              return;
            }

          //update checksum
          ip_h->ip_sum = cksum(ip_h, (ip_h->ip_hl) * 4);

          //Check ARP cache for corresponding MAC address for this packet's IP address
          auto ac_entry = m_arp.lookup(rt_entry.gw);
          if (ac_entry)
            {
              std::cerr << "* Found corresponding MAC address for IP address " << ipToString(rt_entry.gw) << std::endl
                        << "* MAC address: " << macToString(ac_entry->mac) << std::endl;

              ethernet_hdr *eth_h = (ethernet_hdr*)(buf);

              // the problem that prevented packet forwarding was here; the [0] was missing           
              // now ping everywhere works, and transferring small, medium, and large files from client to server1 work
              memcpy(eth_h->ether_dhost, &ac_entry->mac[0], ETHER_ADDR_LEN);

              std::string iname = rt_entry.ifName;
              const Interface * send_interface = findIfaceByName(iname);
              memcpy(eth_h->ether_shost, &send_interface->addr[0], ETHER_ADDR_LEN);
              Buffer pkt_to_send(size);
              memcpy(&pkt_to_send[0], eth_h, sizeof(ethernet_hdr));
              memcpy(&pkt_to_send[14], buf + 14, size - sizeof(ethernet_hdr));
              std::cerr << "* Forwarding packet with headers: \n";

              print_hdrs(pkt_to_send);
              sendPacket(pkt_to_send, iname);
            }

          else
            { 
              std::cerr << "* No corresponding MAC address found for IP address " << ipToString(rt_entry.gw) << std::endl;

              //queue ARP request 
              m_arp.queueRequest(rt_entry.gw, packet, rt_entry.ifName);
              std::cerr << "* Queued arp request\n";
            }
        }
      //end forwarding IP packet
    }
  //end IP packet handling

  //neither IP nor ARP packet
  else 
    std::cerr << "*** Neither IP or ARP packet -> ignore ***\n";
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
