/**
 * @file ipk-sniffer.c
 * @author Filip Botlo xbotlo01
 * @brief 
 * @version 0.1
 * @date 2024-04-21
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h> 
#include <netinet/icmp6.h>
#include <netinet/igmp.h>

#define BUFFER_SIZE 1024
#define TCP 6
#define UDP 17
#define ICMP 1
#define ICMPV6 58
#define ARP_PROTOCOL 0x0806
#define ETHERTYPE_IPV6 0x86dd

// Globálne premenné pre kontrolu filtrov
int interface_flag = 0,
    tcp_flag = 0,
    udp_flag = 0,
    icmp4_flag = 0,
    icmp6_flag = 0, 
    arp_flag = 0, 
    igmp_flag = 0,
    mld_flag = 0,
    ndp_flag = 0;


pcap_t *handle_device = NULL; 


/**
 * Obsluha signálu SIGINT (CTRL+C) pre bezpečné ukončenie programu.
 * Uvoľnenie zdrojov a zatvorenie handle zariadenia.
 * 
 * @param sig Signál SIGINT
 */
void ctr_c_handle(int sig) {
    printf("Terminating and cleaning up...\n");
    if (handle_device != NULL) {
        pcap_breakloop(handle_device);
        pcap_close(handle_device);
    }
    exit(0);
}

/**
 * Funkcia na výpis aktívnych sieťových rozhraní.
 * 
 * @param interfaces Zoznam sieťových rozhraní
 */
void print_active_interfaces(pcap_if_t *interfaces) {
    for (pcap_if_t *iface = interfaces; iface != NULL; iface = iface->next) {
        printf("%s\n", iface->name);
    }
}


/**
 * Funkcia na výpis dát paketu vo formáte hexadecimálneho a textového zápisu.
 * 
 * @param packet Ukazovateľ na paketové dáta
 * @param len Dĺžka paketových dát
 */
void print_packet(const unsigned char *packet, int len) {
    int packet_cnt_hex = 0;
    int packet_cnt_text = 0;
    printf("\n");

    for (int i = 0; i < len / 16 + 1; i++) {
        printf("0x%04x: ", i * 16);
        for (int j = 0; packet_cnt_hex < len && j < 16; j++) {
            printf(" %02x", packet[packet_cnt_hex]);
            if (j == 7) printf(" ");
            packet_cnt_hex++;
        }

        if (len / 16 == i) {
            for (int k = 0; k < 16 - (len % 16); k++) printf("   ");
            if (len % 16 < 8) printf(" ");
        }

        printf("  ");
        for (int j = 0; packet_cnt_text < len && j < 16; j++) {
            if (isprint(packet[packet_cnt_text])) {
                printf("%c", packet[packet_cnt_text]);
            } else {
                printf(".");
            }
            if (j == 7) printf(" ");
            packet_cnt_text++;
        }
        printf("\n");
    }
}


/**
 * Funkcia na výpis hlavičky paketu vrátane informácií o čase, zdrojovom a cieľovom MAC.
 * 
 * @param ether Štruktúra ether_header obsahujúca informácie o pakete
 * @param ts Štruktúra timeval obsahujúca čas príchodu paketu
 * @param len Dĺžka paketu
 */
void print_packet_head(struct ether_header *ether, struct timeval ts, int len) {
    struct tm *time = localtime(&ts.tv_sec);
    char buf[100];
    size_t len_time = strftime(buf, 99, "%FT%T%z", time);
    if (len_time > 1) {
        char minute[] = {buf[len_time - 2], buf[len_time - 1], '\0'};
        sprintf(buf + len_time - 2, ":%s", minute);
    }

    printf("timestamp: %s\n", buf);
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ether->ether_shost[0], ether->ether_shost[1],
           ether->ether_shost[2], ether->ether_shost[3],
           ether->ether_shost[4], ether->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ether->ether_dhost[0], ether->ether_dhost[1],
           ether->ether_dhost[2], ether->ether_dhost[3],
           ether->ether_dhost[4], ether->ether_dhost[5]);
    printf("frame length: %d bytes\n", len);
}



/**
 * @brief Vypíše detaily TCP paketu.
 * 
 * @param packet Ukazovateľ na dáta paketu.
 * @param offset Posun k TCP hlavičke v rámci paketu.
 */
void tcp_packet(const unsigned char *packet, int offset) {
    struct tcphdr *tcp = (struct tcphdr *)(packet + offset);
    printf("src port: %d\n", ntohs(tcp->source));
    printf("dst port: %d\n", ntohs(tcp->dest));
    printf("Protocol: TCP \n");
}

/**
 * @brief Vypíše detaily UDP paketu.
 * 
 * @param packet Ukazovateľ na dáta paketu.
 * @param offset Posun k UDP hlavičke v rámci paketu.
 */
void udp_packet(const unsigned char *packet, int offset) {
    struct udphdr *udp = (struct udphdr *)(packet + offset);
    printf("src port: %d\n", ntohs(udp->source));
    printf("dst port: %d\n", ntohs(udp->dest));
    printf("Protocol: UDP \n");
}

/**
 * @brief Vypíše detaily ARP paketu.
 * 
 * @param packet Ukazovateľ na dáta paketu.
 */
void arp_packet(const unsigned char *packet) {
    struct ether_arp *arp_head = (struct ether_arp *)(packet + sizeof(struct ether_header));
    printf("src IP: %u.%u.%u.%u\n",
           arp_head->arp_spa[0], arp_head->arp_spa[1],
           arp_head->arp_spa[2], arp_head->arp_spa[3]);
    printf("dst IP: %u.%u.%u.%u\n",
           arp_head->arp_tpa[0], arp_head->arp_tpa[1],
           arp_head->arp_tpa[2], arp_head->arp_tpa[3]);
    printf("Protocol: ARP \n");
}

/**
 * @brief Vypíše detaily NDP paketu.
 * 
 * @param packet Ukazovateľ na dáta paketu.
 * @param offset Posun k NDP hlavičke v rámci paketu.
 */
void ndp_packet(const unsigned char *packet, int offset) {
    struct nd_neighbor_solicit *ndp = (struct nd_neighbor_solicit *)(packet + offset);
    char ipv6_addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ndp->nd_ns_target, ipv6_addr_str, INET6_ADDRSTRLEN);
    printf("Target Adress NDP: %s\n", ipv6_addr_str);
}

/**
 * @brief Vypíše detaily ICMP paketu.
 * 
 * @param packet Ukazovateľ na dáta paketu.
 * @param offset Posun k ICMP hlavičke v rámci paketu.
 * @param is_v6 Boolovská hodnota označujúca, či ide o IPv6 paket.
 */
void icmp_packet(const unsigned char *packet, int offset, bool is_v6) {
    if (is_v6) {
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(packet + offset);
        struct ip6_hdr *ipv6 = (struct ip6_hdr *)(packet - sizeof(struct ip6_hdr));
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        
        inet_ntop(AF_INET6, &ipv6->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);
        printf("Type: %d, Code: %d\n", icmp6->icmp6_type, icmp6->icmp6_code);
        printf("Protocol: ICMPv6\n");
    } else {
        struct icmphdr *icmp = (struct icmphdr *)(packet + offset);
        struct ip *ipv4 = (struct ip *)(packet - sizeof(struct ip));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ipv4->ip_src, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipv4->ip_dst, dst_ip, INET_ADDRSTRLEN);

        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);
        printf("Type: %d, Code: %d\n", icmp->type, icmp->code);
        printf("Protocol: ICMPv4 \n");
    }
}

/**
 * @brief Vypíše detaily IGMP paketu.
 * 
 * @param packet Ukazovateľ na dáta paketu.
 * @param offset Posun k IGMP hlavičke v rámci paketu.
 */
void igmp_packet(const unsigned char *packet, int offset) {
    struct igmp *igmp = (struct igmp *)(packet + offset);
    char group_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &igmp->igmp_group.s_addr, group_address, INET_ADDRSTRLEN);
    printf("Group adress IGMP: %s\n", group_address);
}

/**
 * @brief Vypíše detaily MLD paketu.
 * 
 * @param packet Ukazovateľ na dáta paketu.
 * @param offset Posun k MLD hlavičke v rámci paketu.
 */
void mld_packet(const unsigned char *packet, int offset) {
    struct mld_hdr *mld = (struct mld_hdr *)(packet + offset);
    char ipv6_addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &mld->mld_addr, ipv6_addr_str, INET6_ADDRSTRLEN);
    printf("MLD adress: %s\n", ipv6_addr_str);
}

/**
 * @brief Callback funkcia pre spracovanie paketov.
 * 
 * @param user Používateľské dáta (nevyužité).
 * @param header Hlavička paketu.
 * @param packet Dáta paketu.
 */
void packet_parser(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    // Analyzujeme Ethernet hlavičku paketu
    struct ether_header *ether = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(ether->ether_type);
    int ip_offset = sizeof(struct ether_header); // Offset pre IP hlavičku v závislosti na typu Ethernetu

    // Vytlačíme hlavičku paketu
    print_packet_head(ether, header->ts, header->len);

    // Premenné pre IP adresy a ďalšie informácie
    u_int8_t next_protocol;
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];

    // Analyzujeme Ethernet typ paketu
    if (ether_type == ETHERTYPE_IP) {
        // Paket je IPv4
        struct ip *ipv4 = (struct ip *)(packet + ip_offset);
        ip_offset += ipv4->ip_hl * 4; // Posunieme offset na IP dáta
        inet_ntop(AF_INET, &(ipv4->ip_src), src_ip, INET_ADDRSTRLEN); // Prevod z binárnej na textovú formu IP adresy
        inet_ntop(AF_INET, &(ipv4->ip_dst), dst_ip, INET_ADDRSTRLEN);
        next_protocol = ipv4->ip_p; // Typ nasledujúceho protokolu
        printf("src IP: %s\n", src_ip); // Vytlačíme zdrojovú IP adresu
        printf("dst IP: %s\n", dst_ip); // Vytlačíme cieľovú IP adresu
    } else if (ether_type == ETHERTYPE_IPV6) {
        // Paket je IPv6
        struct ip6_hdr *ipv6 = (struct ip6_hdr *)(packet + ip_offset);
        ip_offset += 40; // IPv6 hlavička má fixnú veľkosť 40 bytov
        inet_ntop(AF_INET6, &ipv6->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
        next_protocol = ipv6->ip6_nxt;
        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);
    } else if (ether_type == ETHERTYPE_ARP) {
        // Paket je ARP
        arp_packet(packet); // Spracovanie ARP paketu
        print_packet(packet, header->len); // Vytlačíme celý paket
        printf("\n\n");
        return; // Koniec spracovania
    } else {
        // Neznámy alebo nepodporovaný typ paketu
        printf("Nepodporovaný Ethernet typ: 0x%x\n", ether_type);
        printf("\n\n");
        return; // Koniec spracovania
    }

    // Spracovanie ďalšieho protokolu nad IP (TCP, UDP, ICMP, ICMPv6, IGMP)
    switch (next_protocol) {
        case IPPROTO_TCP:
            tcp_packet(packet, ip_offset); // Spracovanie TCP paketu
            break;
        case IPPROTO_UDP:
            udp_packet(packet, ip_offset); // Spracovanie UDP paketu
            break;
        case IPPROTO_ICMP:
            icmp_packet(packet, ip_offset, false); // Spracovanie ICMP paketu pre IPv4
            break;
        case IPPROTO_ICMPV6:
            if (ndp_flag == 1){
                ndp_packet(packet, ip_offset); // Spracovanie NDP paketu
            }
            if (mld_flag == 1){
                mld_packet(packet, ip_offset); // Spracovanie MLD paketu
            }
            if (icmp6_flag ==1){
                icmp_packet(packet, ip_offset, true); // Spracovanie ICMPv6 paketu
            }
            break;
        case IPPROTO_IGMP:
            igmp_packet(packet, ip_offset); // Spracovanie IGMP paketu
            break;
        default:
            printf("Neznámy alebo nepodporovaný protokol: %d\n", next_protocol);
            break;
    }

    print_packet(packet, header->caplen); // Vytlačíme celý paket
    printf("\n\n");
}





/**
 * @brief Hlavná funkcia programu.
 * 
 * @param argc Počet argumentov príkazového riadka.
 * @param argv Pole reťazcov obsahujúce argumenty príkazového riadka.
 * @return int Vráti EXIT_SUCCESS ak program skončí úspešne, inak EXIT_FAILURE.
 */
int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer pre chybové hlásenia z pcap knižnice
    pcap_if_t *interfaces; // Ukazovateľ na štruktúru pre zoznam rozhraní
    pcap_t *handle; // Ukazovateľ na pcap handler
    struct bpf_program fp; // Štruktúra pre kompilovaný BPF filter
    char filter_exp[BUFFER_SIZE] = ""; // Reťazec pre uchovanie filter výrazu
    bpf_u_int32 mask, net; // Pre uchovanie masky siete a IP adresy siete
    int port = -1; // Premenná pre uchovanie čísla portu
    int opt, num = 1; // Optimalizovaná premenná pre getopt() a počet paketov na zachytávanie
    char port_str[50] = ""; // Reťazec pre uchovanie čísla portu vo forme textu
    char interface[50] = ""; // Reťazec pre uchovanie názvu rozhrania
    int interface_flag = 0; // Premenná na indikáciu, či bolo nastavené rozhranie

    // Hľadanie dostupných rozhraní
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "CHYBA: Žiadne dostupné rozhrania. INFORMÁCIA: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // Ak neboli špecifikované žiadne argumenty príkazového riadka, vypíš aktívne rozhrania
    if (argc < 2) {
        print_active_interfaces(interfaces);
    }

    // Spracovanie argumentov príkazového riadka
    while ((opt = getopt(argc, argv, "i:p:tun:-:")) != -1) {
        switch (opt) {
            case 'i':
                // Nastavenie rozhrania
                if(interface_flag == 1){
                    fprintf(stderr, "CHYBA: Rozhranie už bolo nastavené. INFORMÁCIA: %s\n", errbuf);
                    return EXIT_FAILURE;
                }
                interface_flag = 1;
                if (optarg[0] == '-') {
                    print_active_interfaces(interfaces); // Ak je argument pomlčka, vypíš aktívne rozhrania
                }
                strncpy(interface, optarg, 50); // Kopírovanie názvu rozhrania
                break;
            case 'p':
                // Nastavenie portu
                port = atoi(optarg); // Prevod textového čísla na číslo
                sprintf(port_str, "%d", port); // Prevod čísla portu na text
                if (port <= 0 || port >= 65536) {
                    fprintf(stderr, "Neplatné číslo portu: %d\n", port);
                    exit(EXIT_FAILURE);
                }
                break;
            case 't':
                // Nastavenie TCP flagu
                tcp_flag = 1;
                break;
            case 'u':
                // Nastavenie UDP flagu
                udp_flag = 1;
                break;
            case 'n':
                // Nastavenie počtu paketov na zachytávanie
                num = atoi(optarg);
                break;
            case '-':
                // Rozpoznanie dlhých možností
                if (strcmp(optarg, "tcp") == 0) {
                    tcp_flag = 1; // Nastavenie TCP flagu
                } else if (strcmp(optarg, "udp") == 0) {
                    udp_flag = 1; // Nastavenie UDP flagu
                } else if (strcmp(optarg, "icmp4") == 0) {
                    icmp4_flag = 1; // Nastavenie ICMPv4 flagu
                } else if (strcmp(optarg, "icmp6") == 0) {
                    icmp6_flag = 1; // Nastavenie ICMPv6 flagu
                } else if (strcmp(optarg, "arp") == 0) {
                    arp_flag = 1; // Nastavenie ARP flagu
                } else if (strcmp(optarg, "ndp") == 0) {
                    ndp_flag = 1; // Nastavenie NDP flagu
                } else if (strcmp(optarg, "igmp") == 0) {
                    igmp_flag = 1; // Nastavenie IGMP flagu
                } else if (strcmp(optarg, "mld") == 0) {
                    mld_flag = 1; // Nastavenie MLD flagu
                } else if (strcmp(optarg, "interface") == 0) {
                    // Nastavenie rozhrania
                    if(interface_flag == 1){
                        fprintf(stderr, "CHYBA: Rozhranie už bolo nastavené. INFORMÁCIA: %s\n", errbuf);
                        return EXIT_FAILURE;
                    }
                    interface_flag = 1; // Indikácia, že rozhranie bolo nastavené
                    if (argv[optind] && argv[optind][0] != '-') {
                        strncpy(interface, argv[optind], 50); // Kopírovanie názvu rozhrania
                        optind++;
                    } else {
                        print_active_interfaces(interfaces); // Vypíš aktívne rozhrania
                    }
                }
                break;
        }
    }

    // Ak nebolo nastavené žiadne rozhranie, vypíš aktívne rozhrania
    if (interface_flag == 0) {
        print_active_interfaces(interfaces);
    }

    // Konštrukcia filter výrazu na základe nastavených flagov
    if (mld_flag == 1) {
        strcat(filter_exp, "(icmp6 and (ip6[40] == 130 or ip6[40] == 131 or ip6[40] == 132 or ip6[40] == 143)) or ");
    }
    if (ndp_flag == 1) {
        strcat(filter_exp, "(icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 135 or ip6[40] == 137)) or ");
    }
    if (tcp_flag == 1) {
        if (port != -1) {
            strcat(filter_exp, "tcp port ");
            strcat(filter_exp, port_str);
            strcat(filter_exp, " or ");
        } else {
            strcat(filter_exp, "tcp or ");
        }
    }
    if (udp_flag == 1) {
        if (port != -1) {
            strcat(filter_exp, "udp port ");
            strcat(filter_exp, port_str);
            strcat(filter_exp, " or ");
        } else {
            strcat(filter_exp, "udp or ");
        }
    }
    if (icmp4_flag == 1) {
        strcat(filter_exp, "icmp or ");
    }
    if (icmp6_flag == 1) {
        strcat(filter_exp, "icmp6 or ");
    }
    if (arp_flag == 1) {
        strcat(filter_exp, "arp or ");
    }
    if (igmp_flag == 1) {
        strcat(filter_exp, "igmp or ");
    }

    // Odstrániť "or " zo konca filter výrazu
    if (strlen(filter_exp) > 3) {
        filter_exp[strlen(filter_exp) - 4] = '\0';
    }

    // Získať sieťové parametre rozhrania
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }

    // Otvorenie pcap handleru na živom rozhraní
    handle = pcap_open_live(interface, BUFFER_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        exit(EXIT_FAILURE);
    }

    // Kompilácia filter výrazu
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Nepodarilo sa rozpoznať filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (EXIT_FAILURE);
    }

    // Nastavenie filter výrazu
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Nepodarilo sa nainštalovať filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (EXIT_FAILURE);
    }

    // Zachytenie paketov na základe zadaného počtu
    pcap_loop(handle, num, packet_parser, NULL);

    // Zatvorenie pcap handleru
    pcap_close(handle);

    return EXIT_SUCCESS;
}





