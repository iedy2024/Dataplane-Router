#include <arpa/inet.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>

#define IPV4_ETHER_TYPE 0x0800
#define ARP_ETHER_TYPE 0x0806 
#define ETH_HW_TYPE 1
#define ARP_REQUEST 1
#define ARP_REPLY 2

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;

// Set the general ip headers
void parse_ip_hdr(struct ip_hdr *i_hdr, uint32_t ip_src, uint32_t ip_dst, uint16_t len) {
	i_hdr->tos = 0;
	i_hdr->id = 4;
	i_hdr->frag = 0;
	i_hdr->ihl = 5;
	i_hdr->ver = 4;
	i_hdr->tot_len = htons(len);
	i_hdr->proto = 1;
	i_hdr->ttl = 64;
	i_hdr->source_addr = ip_src;
	i_hdr->dest_addr = ip_dst;
	i_hdr->checksum = 0;
	i_hdr->checksum = htons(checksum((uint16_t *)i_hdr, sizeof(struct ip_hdr)));
}

// Set th general Ethernet headers
void parse_eth_hdr(struct ether_hdr *eth_hdr, uint8_t mac_src[6], 
                   uint8_t mac_dst[6], uint16_t type) {
    eth_hdr->ethr_type = htons(type);
    memcpy(eth_hdr->ethr_shost, mac_src, 6);
    memcpy(eth_hdr->ethr_dhost, mac_dst, 6);
}

// Construct a mac address by a set value
// Used in general to creat brodcast addreses or placeholders
void *make_mac(uint8_t mac[6], int val) {
	for (int i = 0; i < 6; i++) {
		mac[i] = val;
	}
	return mac;
}

// Binary Tire LPM
typedef struct node {
    struct route_table_entry* value;
    struct node* left;
    struct node* right;
}node, *Node;

// Get the actual size of a mac from the address
int get_mask_lenght(uint32_t mask) {
	mask = ntohl(mask);
    size_t len = 0;
    for (int i = 31; i >= 0; i--) {
        if (((mask >> i) & 1) == 1) {
            len++;
        } else {
            break;
        }
    }
    return len;
}

// Initialize the trie
Node init_node(struct route_table_entry* val) {
    Node new_node = (Node)malloc(sizeof(node));
    new_node->value = val;
    new_node->left = new_node->right = NULL;
    return new_node;
}

// Insert a prefix into the trie
Node insert_entry(Node root, struct route_table_entry* val,
                int pref_pos, int mask_len) {
    if (!root) {
        root = init_node(NULL);
    }

    if (!mask_len) {
        root->value = val;
        return root;
    }

	uint32_t prefix = ntohl(val->prefix);
    char current_bit = (prefix >> (31 - pref_pos)) & 1;
    if (current_bit == 0) {
        root->left = insert_entry(root->left, val, pref_pos + 1, mask_len - 1);
    } else {
        root->right = insert_entry(root->right, val, pref_pos + 1, mask_len - 1);
    }
    return root;
}

// Search in the trie the longest matching prefix for and ip
struct route_table_entry* search_node(Node root, uint32_t ip_dest) {
	ip_dest = ntohl(ip_dest);
    Node best = NULL;
    Node temp = root;
    for (int i = 31; i >= 0; i--) {
        if (temp == NULL) {
            break;
        }
        if (temp->value != NULL) {
            best = temp;
        }
        char ip_bit = (ip_dest >> i) & 1;
        if (ip_bit == 0) {
            temp = temp->left;
        } else {
            temp = temp->right;
        }
    }
    if (best != NULL) {
        return best->value;
    }
    return NULL;
}

// Parse roting table entries into a trie
Node form_route_table_tree() {
	Node trie_rtable = init_node(NULL);
	for (int i = 0; i < rtable_len; i++) {
		size_t mask_len = get_mask_lenght(rtable[i].mask);
		insert_entry(trie_rtable, &rtable[i], 0, mask_len);
	}
	return trie_rtable;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	// Search for an entry that matches given_ip, in the arp table

	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
};

char *create_arp_request(size_t interface, uint32_t ip_dst) {
	// Create packet
	char *buf = malloc(sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
	struct ether_hdr *eth_hdr = (struct ether_hdr*)buf;
	struct arp_hdr* a_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	// Get interface MAC and IP
	uint8_t router_mac[6];
	get_interface_mac(interface, router_mac);
	char* router_ip = get_interface_ip(interface);

	// Set Ethernet dest and source
	uint8_t mac_brd[6];
	make_mac(mac_brd, 0xFF);
	parse_eth_hdr(eth_hdr, router_mac, mac_brd, ARP_ETHER_TYPE);

	a_hdr->opcode = htons(ARP_REQUEST);

	// Set arp types
	a_hdr->hw_type = htons(ETH_HW_TYPE);
	a_hdr->proto_type = htons(IPV4_ETHER_TYPE);

	// Set len
	a_hdr->hw_len = 6;
	a_hdr->proto_len = 4;

	// Set source
	memcpy(a_hdr->shwa, router_mac, 6);
	a_hdr->sprotoa = inet_addr(router_ip);
    
	// Set target
	a_hdr->tprotoa = ip_dst;
	uint8_t placeholder_mac[6];
	make_mac(placeholder_mac, 0x00);
	memcpy(a_hdr->thwa, placeholder_mac, 6);

	return buf;
}

struct packet_to_q {
	char *buf;
	size_t len;
};

struct packet_to_q *make_ICMP_packet(uint8_t type, size_t interface,struct ip_hdr* s_i_hdr, uint8_t mac_d[6]) {
	size_t len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr)
				+ sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
	char *buf = malloc(len);
	struct ether_hdr *eth_hdr = (struct ether_hdr*)buf;
	struct ip_hdr* i_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_h = (struct icmp_hdr*)(buf + sizeof(struct ether_hdr)
							+ sizeof(struct ip_hdr));
	char *icmp_bonus_hdr = buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)
						+ sizeof(struct icmp_hdr);

	// Get interface MAC and IP
	uint8_t router_mac[6];
	get_interface_mac(interface, router_mac);
	char* router_ip = get_interface_ip(interface);

	//Ethernet headers
	parse_eth_hdr(eth_hdr, router_mac, mac_d, IPV4_ETHER_TYPE);

	//IP headers
	size_t len_ip = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) 
                + sizeof(struct ip_hdr) + 8;
	parse_ip_hdr(i_hdr, inet_addr(router_ip), s_i_hdr->source_addr, len_ip);

	// ICMP header
	icmp_h->mtype = type;
	icmp_h->mcode = 0;
	memcpy(icmp_bonus_hdr, s_i_hdr, sizeof(struct ip_hdr) + 8);
	icmp_h->check = 0;
	icmp_h->check = htons(checksum((uint16_t*)icmp_h, sizeof(struct icmp_hdr)
					+ sizeof(struct ip_hdr) + 8));
					
	// Send packet + len
	struct packet_to_q *output = malloc(sizeof(struct packet_to_q));
	output->buf = buf;
	output->len = len;
	return output;
}

struct packet_to_q *make_ICMP_reply(size_t interface, uint8_t mac_dst[6], uint32_t ip_dst,
						uint16_t id, uint16_t seq) {
	size_t len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr)
				+ sizeof(struct icmp_hdr);
	char *buf = malloc(len);
	struct ether_hdr *eth_hdr = (struct ether_hdr*)buf;
	struct ip_hdr* i_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_h = (struct icmp_hdr*)(buf + sizeof(struct ether_hdr)
							+ sizeof(struct ip_hdr));
	// Get interface MAC and IP
	uint8_t router_mac[6];
	get_interface_mac(interface, router_mac);
	char* router_ip = get_interface_ip(interface);

	//Ethernet headers
	parse_eth_hdr(eth_hdr, router_mac, mac_dst, IPV4_ETHER_TYPE);

	//IP headers
	size_t len_ip = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
	parse_ip_hdr(i_hdr, inet_addr(router_ip), ip_dst, len_ip);

	// ICMP header
	icmp_h->mtype = 0;
	icmp_h->mcode = 0;
	icmp_h->un_t.echo_t.id = id;
	icmp_h->un_t.echo_t.seq = seq;
	icmp_h->check = 0;
	icmp_h->check = htons(checksum((uint16_t*)icmp_h, sizeof(struct icmp_hdr)));

	// Send packet + len
	struct packet_to_q *output = malloc(sizeof(struct packet_to_q));
	output->buf = buf;
	output->len = len;
	return output;

}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100000);
	DIE(arp_table == NULL, "memory");
	
	// Read the static routing table
	rtable_len = read_rtable(argv[1], rtable);
	// Form a trie with the entries from the routing table
	Node trie_rtable = form_route_table_tree();
	arp_table_len = 0;

	// Making the packet waiting queue
	struct queue *packet_q = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		printf("We have received a packet\n");

    	/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;

		// Check the type of packet
		switch (ntohs(eth_hdr->ethr_type)) {
			case IPV4_ETHER_TYPE: {
				struct ip_hdr *i_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));		
				// Check the i_hdr integrity
				uint16_t csum = checksum((uint16_t *)i_hdr, sizeof(struct ip_hdr));
				printf("TTL: %d, protocol: %d\n", i_hdr->ttl, i_hdr->proto);
				if (csum != 0) {
					printf("Ignored corrupted data\n");
					continue;
				}

				// Look for ICMP Echo request detined to the interface/router
				char *my_ip = get_interface_ip(interface);
				if (i_hdr->dest_addr == inet_addr(my_ip) && i_hdr->proto == 1) {
					// Send a ICMP Echo reply back
					struct icmp_hdr *icmp_h = (struct icmp_hdr*)(buf 
                                + sizeof(struct ether_hdr) 
                                + sizeof(struct ip_hdr));
        			if (icmp_h->mtype == 8) {
            			struct packet_to_q *reply = make_ICMP_reply(interface, eth_hdr->ethr_shost,
						i_hdr->source_addr, icmp_h->un_t.echo_t.id, icmp_h->un_t.echo_t.seq);
            			send_to_link(reply->len, reply->buf, interface);
            			free(reply->buf);
           				free(reply);
					} else {
						printf("Not a ICMP Echo request");
					}
					continue;
				}

				// Find the most specific route, continue; (drop) if null
				struct route_table_entry *route = search_node(trie_rtable, i_hdr->dest_addr);
				if (route == NULL) {
					struct packet_to_q *error_packet =  make_ICMP_packet(3, interface, i_hdr, eth_hdr->ethr_shost);
					send_to_link(error_packet->len, error_packet->buf, interface);
					free(error_packet->buf);
					free(error_packet);
					printf("No route found.");
					continue;
				}

				//Check TTL and update checksum
				if (i_hdr->ttl > 1) {
					i_hdr->ttl--;
					i_hdr->checksum = 0;
					i_hdr->checksum = htons(checksum((uint16_t *)i_hdr, sizeof(struct ip_hdr)));
				} else {
					// Send ICMP Time exceeded error to host
					struct packet_to_q *error_packet =  make_ICMP_packet(11, interface, i_hdr, eth_hdr->ethr_shost);
					send_to_link(error_packet->len, error_packet->buf, interface);
					free(error_packet->buf);
					free(error_packet);
					printf("TTL expired");
					continue;
				}

				// Set Ethernet source
				uint8_t mac_s[6];
				get_interface_mac(route->interface, mac_s);
				memcpy(eth_hdr->ethr_shost, mac_s, 6);

				//Update the ethernet addresses
				struct arp_table_entry *mac_d = get_arp_entry(route->next_hop);
				if (mac_d != NULL) {
					memcpy(eth_hdr->ethr_dhost, mac_d->mac, 6);
				} else {
					// Put the packet in queue and wait for ARP reply
					struct packet_to_q *q_packet = malloc(sizeof(struct packet_to_q));
					q_packet->buf = malloc(len);
					memcpy(q_packet->buf, buf, len);
					q_packet->len = len;
					queue_enq(packet_q, q_packet);

					// Send the ARP request to find destination mac
					char *arp_request = create_arp_request(route->interface, route->next_hop);
					send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_request, route->interface);
					free(arp_request);
					printf("ARP requset sent. Waiting for reply");
					continue;
				}
				
				send_to_link(len, buf, route->interface);
				printf("Packet sent\n");
				break;
			}
			case ARP_ETHER_TYPE: {
				struct arp_hdr* a_hdr = (struct arp_hdr*)(buf + sizeof(struct ether_hdr));
				uint8_t router_mac[6];
				get_interface_mac(interface, router_mac);
				char* router_ip = get_interface_ip(interface);
				if (a_hdr->opcode == htons(ARP_REQUEST)) {	
					if (a_hdr->tprotoa == inet_addr(router_ip)) {
						a_hdr->opcode = htons(ARP_REPLY);

						// Set target MAC & IP
						a_hdr->tprotoa = a_hdr->sprotoa;
						memcpy(a_hdr->thwa, a_hdr->shwa, 6);

						// Set Ethernet headers
						parse_eth_hdr(eth_hdr, router_mac, a_hdr->shwa, ARP_ETHER_TYPE);

						// Set sender MAC & IP
						a_hdr->sprotoa = inet_addr(router_ip);
						memcpy(a_hdr->shwa, router_mac, 6);

						send_to_link(len, buf, interface);
						break;
					} else {
						printf("ARP not for me");
						continue;
					}
				} else if (a_hdr->opcode == htons(ARP_REPLY)) {
					// Register new ARP table entry
					arp_table[arp_table_len].ip = a_hdr->sprotoa;
					memcpy(arp_table[arp_table_len].mac, a_hdr->shwa, 6);
					arp_table_len++;
					printf("ARP reply recived");

					// Resend queued packets
					struct queue *temp_q = create_queue();
					while (!queue_empty(packet_q)) {
						struct packet_to_q *q_packet = queue_deq(packet_q);
						struct ether_hdr *eth_hdr = (struct ether_hdr*)q_packet->buf;
						struct ip_hdr* i_hdr = (struct ip_hdr *)(q_packet->buf + sizeof(struct ether_hdr));
						struct route_table_entry *route = search_node(trie_rtable, i_hdr->dest_addr);
						if (route->next_hop == a_hdr->sprotoa) {
							memcpy(eth_hdr->ethr_dhost, a_hdr->shwa, 6);
							send_to_link(q_packet->len, q_packet->buf, route->interface);
							free(q_packet->buf);
							free(q_packet);
							printf("Sending packet from q");
						} else {
							queue_enq(temp_q, q_packet);
						}
					}
					packet_q = temp_q;
				}
				break;
			}
			default: {
				printf("Ignored non-IPv4 and APR packets");
				continue;
			}
		}
	}
		
}

