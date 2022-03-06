/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

  //*** receive arp reply -> send requested packets ***
void
ArpCache::send_pending_packets(struct arp_hdr &reply_arp_hdr, uint32_t dest_ip)
{
  std::shared_ptr<ArpRequest> request = nullptr;
  for(const auto& r : m_arpRequests)
    {
      if(r->ip == dest_ip)
        {
          request = r;
          break;
        }
    }

  //send queued packets 
  if(request != nullptr)
    {
      for(const auto& pendingpackets: request->packets)
        {
          int packet_size = pendingpackets.packet.size();
          Buffer buf (packet_size, 0);
          struct ethernet_hdr eth_hdr;

          memcpy(eth_hdr.ether_dhost, &reply_arp_hdr.arp_sha[0], ETHER_ADDR_LEN);
          memcpy(eth_hdr.ether_shost, &reply_arp_hdr.arp_tha[0], ETHER_ADDR_LEN);
          eth_hdr.ether_type = htons(0x0800);

          memcpy(&buf[0], &eth_hdr, sizeof(eth_hdr));
          memcpy(&buf[14], &pendingpackets.packet[14], packet_size - sizeof(eth_hdr));

          std::string iname = m_router.getRoutingTable().lookup(dest_ip).ifName;
          const Interface* send_interface = m_router.findIfaceByName(iname);
          m_router.sendPacket(buf, send_interface->name);
        }

      m_arpRequests.remove(request);
    }
}

  //*** want to send packets -> send arp request repeatedly ***
void
ArpCache::outgoing_arp_request(std::shared_ptr<ArpRequest> request, bool &isremoved)
{
    //1 second has passed or request sent 5 times 
    if(steady_clock::now() - request->timeSent > seconds(1))
    {
      //stop sending
      if(request->nTimesSent >= MAX_SENT_TIME)
        {
          printf("* Number of times sent ARP request: %d\n", request->nTimesSent);
          printf("* No reply for ARP request -> remove request\n");
          m_arpRequests.remove(request);
          isremoved = true;
          return;
        }

      //send again
      else
        {
          struct arp_hdr arp_header;
          struct ethernet_hdr eth_header;
          Buffer buf (42,0);

          //interface
          std::string iname = m_router.getRoutingTable().lookup(request->ip).ifName;
          const Interface* send_interface = m_router.findIfaceByName(iname);

          //ethernet frame
          memset(eth_header.ether_dhost, 255, ETHER_ADDR_LEN);
          memcpy(eth_header.ether_shost, &send_interface->addr[0], ETHER_ADDR_LEN);
          eth_header.ether_type = htons(0x0806);
          //print_hdr_eth((uint8_t*)&eth_header);

          //arp header
          arp_header.arp_hrd = htons(0x0001);
          arp_header.arp_pro = htons(0x0800);
          arp_header.arp_hln = 6;
          arp_header.arp_pln = 4;
          arp_header.arp_op = htons(0x0001);
          memcpy(arp_header.arp_sha, &send_interface->addr[0], ETHER_ADDR_LEN);
          memcpy(&arp_header.arp_sip, &send_interface->ip, sizeof(arp_header.arp_sip));
          memset(arp_header.arp_tha, 255, ETHER_ADDR_LEN);
          memcpy(&arp_header.arp_tip, &request->ip, sizeof(arp_header.arp_tip));
          //print_hdr_arp((uint8_t*)&arp_header);

          //Send packets 
          memcpy(&buf[0], &eth_header, sizeof(eth_header));
          memcpy(&buf[14], &arp_header, sizeof(arp_header));
          m_router.sendPacket(buf, send_interface->name);

          request->timeSent = steady_clock::now();
          request->nTimesSent++;
        }
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  bool isremoved = false;
  std::vector<std::shared_ptr<ArpEntry>> to_remove;
  for(const auto& request : m_arpRequests)
    {
      outgoing_arp_request(request, isremoved);
      if(isremoved)
      break;
    }

  //find stale arp cache entries and add them to vector of ArpEntrys to_remove
  for(const auto& entry : m_cacheEntries)
    {
      if(!(entry->isValid))
        {
          to_remove.push_back(entry);
        }
    }

  //remove the stale entries from arp cache 
  for(const auto& entry : to_remove)
    {
      m_cacheEntries.remove(entry);
    }
}
  
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
