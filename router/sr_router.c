/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
  Check source ip with ip_blacklist
  Goal 1 : check whether the source ip is black ip or not
  Goal 2 : Print Log
  - Format  :  " [Source ip blocked] : <source ip> "
  e.g.) [Source ip blocked] : 10.0.2.100
*/
int ip_black_list(struct sr_ip_hdr *iph)
{
  int blk = 0;
  char ip_blacklist[20] = "10.0.2.0";
  char mask[20] = "255.255.255.0";
  /**************** fill in code here *****************/
  struct in_addr addr;
  uint32_t src;
  inet_pton(AF_INET, ip_blacklist, &addr);
  src = ntohl(addr.s_addr); //1010 00000000 00000010 00000000

  uint32_t mas;
  inet_pton(AF_INET, mask, &addr);
  mas = ntohl(addr.s_addr); //11111111 11111111 11111111 00000000

  if ((ntohl(iph->ip_src) & mas) == src)
  {
    fprintf(stderr, "[Source ip blocked] : ");
    print_addr_ip_int(ntohl(iph->ip_src));
    blk = 1;
  }

  /****************************************************/
  return blk;
}
/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  // fprintf(stderr, "\n\n***********Recive Start***************\n");
  // print_hdrs(packet, len);
  // fprintf(stderr, "**************Recive End************\n\n");

  // fprintf(stderr, "[INFO] interface of sr_handlepacket is : %s\n",interface);

  // fprintf(stderr, "\n\n***********Current ARP cache Start***************\n");
  // sr_arpcache_dump(&sr->cache);
  // fprintf(stderr, "\n\n***********Current ARP cache End***************\n");
  //print_hdrs(packet,len);

  /*  printf("*** -> Received packet of length %d \n",len);*/

  /* fill in code here */
  uint8_t *new_pck;     /* new packet */
  unsigned int new_len; /* length of new_pck */

  unsigned int len_r; /* length remaining, for validation */
  uint16_t checksum;  /* checksum, for validation */

  struct sr_ethernet_hdr *e_hdr0, *e_hdr; /* Ethernet headers */
  struct sr_ip_hdr *i_hdr0, *i_hdr;       /* IP headers */
  struct sr_arp_hdr *a_hdr0, *a_hdr;      /* ARP headers */
  struct sr_icmp_hdr *ic_hdr0;            /* ICMP header */
  struct sr_icmp_t3_hdr *ict3_hdr;        /* ICMP type3 header */

  struct sr_if *ifc;            /* router interface */
  uint32_t ipaddr;              /* IP address */
  struct sr_rt *rtentry;        /* routing table entry */
  struct sr_arpentry *arpentry; /* ARP table entry in ARP cache */
  struct sr_arpreq *arpreq;     /* request entry in ARP cache */
  struct sr_packet *en_pck;     /* encapsulated packet in ARP cache */

  /* validation */
  if (len < sizeof(struct sr_ethernet_hdr))
    return;
  len_r = len - sizeof(struct sr_ethernet_hdr);
  e_hdr0 = (struct sr_ethernet_hdr *)packet; /* e_hdr0 set */

  /* IP packet arrived */
  if (e_hdr0->ether_type == htons(ethertype_ip))
  {
    fprintf(stderr, "[INFO] IP packet arrived\n");
    /* validation */
    if (len_r < sizeof(struct sr_ip_hdr))
      return;
    len_r = len_r - sizeof(struct sr_ip_hdr);
    i_hdr0 = (struct sr_ip_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* i_hdr0 set */
    if (i_hdr0->ip_v != 0x4)
      return;
    checksum = i_hdr0->ip_sum;
    i_hdr0->ip_sum = 0;
    if (checksum != cksum(i_hdr0, sizeof(struct sr_ip_hdr)))
      return;
    i_hdr0->ip_sum = checksum;

    /* check destination */
    for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next)
      if (i_hdr0->ip_dst == ifc->ip)
      {
        break;
      }
    // fprintf(stderr, "[INFO] router interface list Start\n");
    // sr_print_if_list(sr);
    // fprintf(stderr, "[INFO] router interface list End\n");
    /* check ip black list */
    if (ip_black_list(i_hdr0))
    {
      /* Drop the packet */
      return;
    }

    /* destined to router interface */
    if (ifc != NULL)
    {
      fprintf(stderr, "[INFO] destined to router interface\n");
      fprintf(stderr, "[INFO] destination ifc is : %s\n",ifc->name);

      /* with ICMP */
      if (i_hdr0->ip_p == ip_protocol_icmp)
      {
        fprintf(stderr, "[INFO] with ICMP\n");
        /* validation */
        if (len_r < sizeof(struct sr_icmp_hdr))
          return;
        ic_hdr0 = (struct sr_icmp_hdr *)(((uint8_t *)i_hdr0) + sizeof(struct sr_ip_hdr)); /* ic_hdr0 set */

        /* echo request type */
        if (ic_hdr0->icmp_type == 0x08)
        {
          fprintf(stderr, "[INFO] echo request type\n");
          /* validation */
          checksum = ic_hdr0->icmp_sum;
          ic_hdr0->icmp_sum = 0;
          if (checksum != cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)))
            return;
          ic_hdr0->icmp_sum = checksum;

          /* modify to echo reply */
          i_hdr0->ip_ttl = INIT_TTL;
          ipaddr = i_hdr0->ip_src;
          i_hdr0->ip_src = i_hdr0->ip_dst;
          i_hdr0->ip_dst = ipaddr;
          i_hdr0->ip_sum = 0;
          i_hdr0->ip_sum = cksum(i_hdr0, sizeof(struct sr_ip_hdr));
          ic_hdr0->icmp_type = 0x00;
          ic_hdr0->icmp_sum = 0;
          ic_hdr0->icmp_sum = cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
          rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);
          if (rtentry != NULL)
          {
            ifc = sr_get_interface(sr, rtentry->interface);
            memcpy(e_hdr0->ether_shost, ifc->addr, ETHER_ADDR_LEN);
            arpentry = sr_arpcache_lookup(&(sr->cache), rtentry->gw.s_addr);
            if (arpentry != NULL)
            {
              memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
              free(arpentry);
              /* send */
              sr_send_packet(sr, packet, len, rtentry->interface);
            }
            else
            {
              /* queue */
              arpreq = sr_arpcache_queuereq(&(sr->cache), rtentry->gw.s_addr, packet, len, rtentry->interface);
              sr_arpcache_handle_arpreq(sr, arpreq);
            }
          }

          /* done */
          return;
        }

        /* other types */
        else
          return;
      }

      /* with TCP or UDP */
      else if (i_hdr0->ip_p == ip_protocol_tcp || i_hdr0->ip_p == ip_protocol_udp)
      {
        fprintf(stderr, "[INFO] with TCP or UDP\n");
        /* validation */
        if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
          return;

        /**************** fill in code here *****************/
        /* generate ICMP port unreachable packet */
        new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
        new_pck = (uint8_t *)calloc(1, new_len);

        /* send */

        /* queue */

        /*****************************************************/
        /* done */
        free(new_pck);
        return;
      }

      /* with others */
      else
        return;
    }
    /* destined elsewhere, forward */
    else
    { //路由转发
      fprintf(stderr, "[INFO] destined elsewhere, forward \n");
      /* refer routing table */
      rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);//192.168.2.2

      /* hit */
      if (rtentry != NULL)
      {
         fprintf(stderr, "[INFO] forward %s\n",rtentry->interface);

        /**************** fill in code here *****************/
        /* check TTL expiration */
        if (i_hdr0->ip_ttl == 1)
        {
          fprintf(stderr, "TTL equal 1\n");
          /* validation */
          if (len_r < sizeof(struct sr_icmp_hdr))
          {
            fprintf(stderr, "Failed to validate ICMP header: insufficient length\n");
            return;
          }
          ic_hdr0 = (struct sr_icmp_hdr *)(((uint8_t *)i_hdr0) + sizeof(struct sr_ip_hdr)); /* ic_hdr0 set */

          checksum = ic_hdr0->icmp_sum;
          ic_hdr0->icmp_sum = 0;
          if (checksum != cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)))
          {
            fprintf(stderr, "Failed to validate ICMP header: incorrect checksum.\n");
            return;
          }
          ic_hdr0->icmp_sum = checksum;

          /* generate ICMP time exceeded packet */
          fprintf(stderr, "generate ICMP time exceeded packet... \n");

          new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
          new_pck = malloc(new_len);

          /*ICMP Header*/
          fprintf(stderr, " (make ICMP exceeded Header)... \n");
          ict3_hdr = (sr_icmp_t3_hdr_t *)malloc(sizeof(sr_icmp_t3_hdr_t));
          ict3_hdr->icmp_type = 11;
          ict3_hdr->icmp_code = 0;
          ict3_hdr->unused = 0;
          memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
          ict3_hdr->icmp_sum = 0;
          ict3_hdr->icmp_sum = cksum(ict3_hdr, sizeof(struct sr_icmp_t3_hdr));
          // print_hdr_icmp(ict3_hdr);

          /*IP Header*/
          fprintf(stderr, " (make IP exceeded Header)... \n");
          i_hdr = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
          i_hdr->ip_v = 4;
          i_hdr->ip_hl = 5;
          i_hdr->ip_tos = 0;
          i_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(struct sr_icmp_t3_hdr));
          i_hdr->ip_id = htons(i_hdr0->ip_id) + 1;
          i_hdr->ip_off = htons(IP_DF);
          i_hdr->ip_ttl = INIT_TTL;
          i_hdr->ip_p = ip_protocol_icmp;

          ifc = sr_get_interface(sr, interface);
          i_hdr->ip_src = ifc->ip;
          i_hdr->ip_dst = i_hdr0->ip_src;

          i_hdr->ip_sum = 0;
          i_hdr->ip_sum = cksum(i_hdr, sizeof(sr_ip_hdr_t));
          // print_hdr_ip(i_hdr);

          fprintf(stderr, " (make Ethernet exceeded Header)... \n");
          e_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
          e_hdr->ether_type = htons(ethertype_ip);
          memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);

          //
          fprintf(stderr,"[INFO] need to find arp entry\n");
          //print_addr_ip(rtentry->gw.s_addr);
          //查找目的MAC地址
          sr_arpcache_dump(&sr->cache);
          arpentry = sr_arpcache_lookup(&(sr->cache), i_hdr0->ip_src);
          if (arpentry != NULL)
          {
            fprintf(stderr, "Has ARP entry\n");
            memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
            free(arpentry);

            memcpy(new_pck, e_hdr, sizeof(sr_ethernet_hdr_t));
            memcpy(new_pck + sizeof(sr_ethernet_hdr_t), i_hdr, sizeof(sr_ip_hdr_t));
            memcpy(new_pck + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ict3_hdr, sizeof(struct sr_icmp_t3_hdr));
            // fprintf(stderr, "\n***********New Packet************\n");
            // print_hdrs(new_pck, new_len);
            // fprintf(stderr, "***********New Packet************\n\n");
            /* send */
            fprintf(stderr, "send to %s\n",interface);
            sr_send_packet(sr, new_pck, new_len, interface);
          }
          else
          {
            fprintf(stderr, "No ARP entry\n");
            memcpy(new_pck, e_hdr, sizeof(sr_ethernet_hdr_t));
            memcpy(new_pck + sizeof(sr_ethernet_hdr_t), i_hdr, sizeof(sr_ip_hdr_t));
            memcpy(new_pck + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ict3_hdr, sizeof(struct sr_icmp_t3_hdr));

            // fprintf(stderr, "\n***********New Packet************\n");
            // print_hdrs(new_pck, new_len);
            // fprintf(stderr, "***********New Packet************\n\n");
            /* queue */
            arpreq = sr_arpcache_queuereq(&(sr->cache), i_hdr->ip_dst, new_pck, new_len, interface);
            sr_arpcache_handle_arpreq(sr, arpreq);
          }
          free(ict3_hdr);
          free(i_hdr);
          free(e_hdr);
          /*****************************************************/
          /* done */
          free(new_pck);
          return;
        }


        fprintf(stderr, "TTL not equal 1\n");
        /**************** fill in code here *****************/

        /* set src MAC addr */
        ifc = sr_get_interface(sr, rtentry->interface);
        fprintf(stderr, "rtentry ifc is : %s\n",ifc->name);

        memcpy(e_hdr0->ether_shost, ifc->addr, ETHER_ADDR_LEN);
        /* refer ARP table */
        arpentry = sr_arpcache_lookup(&(sr->cache), rtentry->gw.s_addr);
        /* hit */
        if (arpentry != NULL)
        {
          /* set dst MAC addr */
          memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
          free(arpentry);
          /* decrement TTL */
          i_hdr0->ip_ttl -= 1;
          i_hdr0->ip_sum = 0;
          i_hdr0->ip_sum = cksum(i_hdr0, sizeof(sr_ip_hdr_t));
          /* forward */
          sr_send_packet(sr, packet, len, rtentry->interface);

          /*****************************************************/
        }
        /* miss */
        else
        {
          /* queue */
          arpreq = sr_arpcache_queuereq(&(sr->cache), rtentry->gw.s_addr, packet, len, rtentry->interface);
          sr_arpcache_handle_arpreq(sr, arpreq);
        }
        /* done */
        return;
      }
      /* miss */
      else
      {
        /**************** fill in code here *****************/
        fprintf(stderr, "[INFO] rtentry is empty!\n");
        /* validation */
        new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
        new_pck = (uint8_t *)calloc(1, new_len);
        /* generate ICMP net unreachable packet */

        /* send */

        /* queue */

        /*****************************************************/
        /* done */
        free(new_pck);
        return;
      }
    }
  }
  /* ARP packet arrived */
  else if (e_hdr0->ether_type == htons(ethertype_arp))
  {
    fprintf(stderr, "[INFO] ARP packet arrived \n");
    /* validation */
    if (len_r < sizeof(struct sr_arp_hdr))
      return;

    a_hdr0 = (struct sr_arp_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* a_hdr0 set */

    /* destined to me */
    ifc = sr_get_interface(sr, interface);
    if (a_hdr0->ar_tip == ifc->ip)
    {
      /* request code */
      if (a_hdr0->ar_op == htons(arp_op_request))
      {
        fprintf(stderr, "[INFO] request code\n");

        // fprintf(stderr, "Received ARP request (Source: ");
        // print_addr_ip_int(ntohl(a_hdr0->ar_sip));
        // fprintf(stderr, " Target: ");
        // print_addr_ip_int(ntohl(a_hdr0->ar_tip));

        // fprintf(stderr, "Sending ARP reply to ");
        // print_addr_ip_int(ntohl(a_hdr0->ar_sip));
        /**************** fill in code here *****************/
        /* generate reply */
        new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        new_pck = malloc(new_len);
        fprintf(stderr, " (make ARP Reply Header)... \n");
        a_hdr = (sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
        a_hdr->ar_hrd = htons(arp_hrd_ethernet);               //硬件类型
        a_hdr->ar_pro = htons(ethertype_ip);                   //协议类型
        a_hdr->ar_hln = ETHER_ADDR_LEN;                        //硬件地址长度
        a_hdr->ar_pln = sizeof(uint32_t);                      //IP地址长度
        a_hdr->ar_op = htons(arp_op_reply);                    //操作码
        memcpy(a_hdr->ar_sha, ifc->addr, ETHER_ADDR_LEN);      //发送方的硬件地址
        memcpy(a_hdr->ar_tha, a_hdr0->ar_sha, ETHER_ADDR_LEN); //目标方的硬件地址
        a_hdr->ar_sip = a_hdr0->ar_tip;                        //发送方的IP地址
        a_hdr->ar_tip = a_hdr0->ar_sip;                        //目标方的IP地址

        fprintf(stderr, " (make Ethernet Header)... \n");
        e_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
        memcpy(e_hdr->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
        memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
        e_hdr->ether_type = htons(ethertype_arp);

        new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        new_pck = malloc(new_len);
        memcpy(new_pck, e_hdr, sizeof(sr_ethernet_hdr_t));
        memcpy(new_pck + sizeof(sr_ethernet_hdr_t), a_hdr, sizeof(sr_arp_hdr_t));

        arpreq = sr_arpcache_insert(&(sr->cache),a_hdr0->ar_sha,a_hdr0->ar_sip);
        if(arpentry != NULL)
        {
          sr_arpcache_dump(&sr->cache);
        }
        else
        {
          /* code */
          fprintf(stderr, "arpreq is empty!\n");
        }

        print_hdrs(new_pck, new_len);
        /* send */
        fprintf(stderr,"send arp reply  from %s\n",interface);
        sr_send_packet(sr, new_pck, new_len, interface);

        /*****************************************************/
        /* done */
        free(e_hdr);
        free(a_hdr);
        free(new_pck);
        return;
      }

      /* reply code */
      else if (a_hdr0->ar_op == htons(arp_op_reply))
      {
        fprintf(stderr, "[INFO] reply code\n");
        /**
         * 如果收到一个ARP 响应报文
         * 将MAC IP 的映射 插入到路由表的ARP cache中
         * 然后将该数据报的目的MAC地址 就是当时ICMP未完成的部分进行完成 发送ICMP时不知道目的MAC地址
         * 所以发送了一个ARP请求报文
         */
        /**************** fill in code here *****************/
        // fprintf(stderr, "Received ARP reply (Source: ");
        // print_addr_ip_int(ntohl(a_hdr0->ar_sip));
        // fprintf(stderr, " Target: ");
        // print_addr_ip_int(ntohl(a_hdr0->ar_tip));
        // fprintf(stderr, ")\n");
        /* pass info to ARP cache */
        arpreq = sr_arpcache_insert(&sr->cache, a_hdr0->ar_sha, a_hdr0->ar_sip);
        //sr_arpcache_dump(&sr->cache);
        /* pending request exist */
        if (arpreq != NULL)
        {
          fprintf(stderr, "New entry inserted, ARP Cache Table:\n");
          /* set dst MAC addr */
          e_hdr = (struct sr_ethernet_hdr *)arpreq->packets;
          memcpy(e_hdr->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
          /* decrement TTL except for self-generated packets */
          i_hdr = (sr_ip_hdr_t*)(e_hdr + sizeof(sr_ethernet_hdr_t));
          i_hdr->ip_ttl -= 1;
          i_hdr->ip_sum = 0;
          i_hdr->ip_sum = cksum(i_hdr, sizeof(sr_ip_hdr_t));
          /* send */

          print_hdrs(arpreq->packets, arpreq->packets->len);

          // fprintf(stderr,"%s\n",ifc->name);
          // print_hdrs(arpreq->packets, arpreq->packets->len);
          sr_send_packet(sr, arpreq->packets, arpreq->packets->len, ifc);
          /* done */
          sr_arpreq_destroy(&(sr->cache), arpreq);
          return;
        }

        /*****************************************************/
        /* no exist */
        else
          return;
      }

      /* other codes */
      else
        return;
    }

    /* destined to others */
    else
      return;
  }

  /* other packet arrived */
  else
    return;

} /* end sr_ForwardPacket */

struct sr_rt *sr_findLPMentry(struct sr_rt *rtable, uint32_t ip_dst)
{
  struct sr_rt *entry, *lpmentry = NULL;
  uint32_t mask, lpmmask = 0;

  ip_dst = ntohl(ip_dst);

  /* scan routing table */
  for (entry = rtable; entry != NULL; entry = entry->next)
  {
    mask = ntohl(entry->mask.s_addr);
    /* longest match so far */
    if ((ip_dst & mask) == (ntohl(entry->dest.s_addr) & mask) && mask > lpmmask)
    {
      lpmentry = entry;
      lpmmask = mask;
    }
  }

  return lpmentry;
}
