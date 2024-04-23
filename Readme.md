# IPK Projekt 2 - ZETA: Sieťový Sniffer

Tento projekt je zameraný na návrh a implementáciu sieťového analyzátora schopného zachytávať a filtrovať pakety na špecifickom sieťovom rozhraní. Podporované sú protokoly TCP, UDP, ARP, ICMP, ICMPv6 a podpora pre IPv4 a IPv6 adresy.

## Autor

Filip Botlo / xbotlo01

## Kompilácia a Spustenie

Program `sniffer`sa prekladá a spúšťa nasledovne:

```bash
$ make
$ ./ipk-sniffer [-i rozhranie | --interface rozhranie] {-p|--port-source|--port-destination port} [--tcp|-t] [--udp|-u] [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] [-n num]
```

## Parametre

-i, --interface: Určuje sieťové rozhranie pre zachytávanie. Vypíše dostupné rozhrania, ak nie je špecifikované.
-p, --port-source, --port-destination: Filtre založené na zdrojovom alebo cieľovom porte.
--tcp, -t: Zobrazí len TCP segmenty.
--udp, -u: Zobrazí len UDP datagramy.
--arp: Zobrazí len ARP rámce.
--icmp4: Zobrazí len ICMPv4 pakety.
--icmp6: Zobrazí len ICMPv6 echo request/response.
--igmp, --mld: Zobrazí len IGMP alebo MLD pakety.
-n: Počet paketov na zobrazenie; predvolená hodnota je 1.


## Funkcie

Zachytáva pakety v promiskuitnom móde.
Vypisuje časovú pečiatku, MAC adresy, dĺžku rámca, IP adresy, porty a obsah paketu.
Podpora pre rôzne typy hlavičiek a protokolov.
Umožňuje ukončenie programu pomocou sekvenčnej klávesovej skratky Ctrl+C.


***
## Príklad spustenia

```
$ sudo ./sniffer -i wlp3s0 --tcp -n 2

timestamp: 2024-04-21T19:38:42+02:00
src MAC: 02:10:18:ea:50:7c
dst MAC: 20:2b:20:d3:76:0b
frame length: 125 bytes
src IP: 162.159.136.234
dst IP: 192.168.0.218
src port: 443
dst port: 43468
protocol type: TCP

0x0000:  20 2b 20 d3 76 0b 02 10  18 ea 50 7c 08 00 45 00   + .v... ..P|..E.
0x0010:  00 6f a1 16 40 00 3b 06  b1 66 a2 9f 88 ea c0 a8  .o..@.;. .f......
0x0020:  00 da 01 bb a9 cc 89 8d  af 61 57 e0 59 db 80 18  ........ .aW.Y...
0x0030:  00 08 8e 03 00 00 01 01  08 0a de ec ec fb 3d 60  ........ ......=`
0x0040:  e3 75 17 03 03 00 36 ec  f4 5e cd bc 6b 89 82 83  .u....6. .^..k...
0x0050:  8e 37 4a 80 1b a7 37 7a  11 12 d3 8a 88 4e 24 35  .7J...7z .....N$5
0x0060:  b9 5c dd fd 4e f0 d7 78  73 5a ae ee 00 52 3e 71  .\..N..x sZ...R>q
0x0070:  a3 73 cc 5a 2a 0f 2b 8d  6c b3 3c 71 2d           .s.Z*.+. l.<q-


timestamp: 2024-04-21T19:38:42+02:00
src MAC: 20:2b:20:d3:76:0b
dst MAC: 02:10:18:ea:50:7c
frame length: 66 bytes
src IP: 192.168.0.218
dst IP: 162.159.136.234
src port: 43468
dst port: 443
protocol type: TCP

0x0000:  02 10 18 ea 50 7c 20 2b  20 d3 76 0b 08 00 45 00  ....P| +  .v...E.
0x0010:  00 34 49 03 40 00 40 06  04 b5 c0 a8 00 da a2 9f  .4I.@.@. ........
0x0020:  88 ea a9 cc 01 bb 57 e0  59 db 89 8d af 9c 80 10  ......W. Y.......
0x0030:  01 f5 00 42 00 00 01 01  08 0a 3d 60 e7 c3 de ec  ...B.... ..=`....
0x0040:  ec fb
```

## Testovanie a výstupy

Pre fotografie porovnania s programom Wireshark pozrite manuál.


```
root@aladix-Aspire:/home/aladix/Desktop/sniffer# ./ipk-sniffer --interface    
wlp3s0
any
lo
enp2s0
docker0
nflog
nfqueue
root@aladix-Aspire:/home/aladix/Desktop/sniffer# 
```

```
root@aladix-Aspire:/home/aladix/Desktop/sniffer# ./ipk-sniffer -i wlp3s0      
timestamp: 2024-04-22T15:43:27+02:00
src MAC: 02:10:18:ea:50:7c
dst MAC: 20:2b:20:d3:76:0b
frame length: 147 bytes
src IP: 162.159.130.234
dst IP: 192.168.0.218
src port: 443
dst port: 46784
Protokol: TCP 

0x0000:  20 2b 20 d3 76 0b 02 10  18 ea 50 7c 08 00 45 00   + .v... ..P|..E.
0x0010:  00 85 9e 29 40 00 3b 06  ba 3d a2 9f 82 ea c0 a8  ...)@.;. .=......
0x0020:  00 da 01 bb b6 c0 25 a1  d2 26 17 ae d7 d3 80 18  ......%. .&......
0x0030:  00 08 5d c7 00 00 01 01  08 0a d7 18 2e 83 4b a9  ..]..... ......K.
0x0040:  16 56 17 03 03 00 4c c7  3d 0c 71 14 f5 10 dc 4b  .V....L. =.q....K
0x0050:  9e bb 5a b7 62 0e 8b 6d  39 e6 33 8c f9 ea 98 9f  ..Z.b..m 9.3.....
0x0060:  a2 12 7b ce d7 d6 54 2e  48 55 92 c3 d9 56 98 6c  ..{...T. HU...V.l
0x0070:  e2 ff 57 a8 d5 d0 4e f0  8c 07 42 de 0e 17 3e a8  ..W...N. ..B...>.
0x0080:  30 a1 de bb 1c fa 32 a6  19 c8 27 86 65 12 e5 42  0.....2. ..'.e..B
0x0090:  26 82 3a                                          &.:
```

```
root@aladix-Aspire:/home/aladix/Desktop/sniffer# ./ipk-sniffer -i wlp3s0 --tcp -n 2
timestamp: 2024-04-22T15:52:05+02:00
src MAC: 02:10:18:ea:50:7c
dst MAC: 20:2b:20:d3:76:0b
frame length: 171 bytes
src IP: 149.154.167.91
dst IP: 192.168.0.218
src port: 443
dst port: 38850
Protokol: TCP 

0x0000:  20 2b 20 d3 76 0b 02 10  18 ea 50 7c 08 00 45 00   + .v... ..P|..E.
0x0010:  00 9d b8 5d 40 00 32 06  91 85 95 9a a7 5b c0 a8  ...]@.2. .....[..
0x0020:  00 da 01 bb 97 c2 82 b8  45 77 31 39 f3 ce 80 18  ........ Ew19....
0x0030:  19 ec 54 e0 00 00 01 01  08 0a b5 18 ee 15 78 91  ..T..... ......x.
0x0040:  a7 4e c5 5d 99 30 c9 ac  58 d7 f0 4c d0 23 14 86  .N.].0.. X..L.#..
0x0050:  25 1e 3c 4c 0f c3 ea 2c  b9 f0 79 07 a1 03 36 45  %.<L..., ..y...6E
0x0060:  55 fc 1f a2 36 e6 61 c8  33 2c 69 d9 7a 98 af 74  U...6.a. 3,i.z..t
0x0070:  92 a5 a7 eb d5 c3 cc 39  f3 e4 b0 e7 e0 9a 31 11  .......9 ......1.
0x0080:  bc 50 db 3d a9 35 77 c5  ab 49 a5 dc 11 c3 6b 9a  .P.=.5w. .I....k.
0x0090:  fa b3 e6 81 64 4b ca 9c  71 a0 f6 bc 66 cf 88 ed  ....dK.. q...f...
0x00a0:  2a 36 21 87 64 ac ef d9  d0 ad 3b                 *6!.d... ..;


timestamp: 2024-04-22T15:52:05+02:00
src MAC: 20:2b:20:d3:76:0b
dst MAC: 02:10:18:ea:50:7c
frame length: 66 bytes
src IP: 192.168.0.218
dst IP: 149.154.167.91
src port: 38850
dst port: 443
Protokol: TCP 

0x0000:  02 10 18 ea 50 7c 20 2b  20 d3 76 0b 08 00 45 00  ....P| +  .v...E.
0x0010:  00 34 e9 c7 40 00 40 06  52 84 c0 a8 00 da 95 9a  .4..@.@. R.......
0x0020:  a7 5b 97 c2 01 bb 31 39  f3 ce 82 b8 45 e0 80 10  .[....19 ....E...
0x0030:  0a 08 18 7f 00 00 01 01  08 0a 78 91 b2 df b5 18  ........ ..x.....
0x0040:  ee 15          
```

```
root@aladix-Aspire:/home/aladix/Desktop/sniffer# ./ipk-sniffer -i wlp3s0 --udp
timestamp: 2024-04-22T15:57:05+02:00
src MAC: 7e:10:92:9e:41:d5
dst MAC: 01:00:5e:00:00:fb
frame length: 124 bytes
src IP: 192.168.0.58
dst IP: 224.0.0.251
src port: 5353
dst port: 5353
Protokol: UDP 

0x0000:  01 00 5e 00 00 fb 7e 10  92 9e 41 d5 08 00 45 00  ..^...~. ..A...E.
0x0010:  00 6e 35 ec 00 00 ff 11  e3 b4 c0 a8 00 3a e0 00  .n5..... .....:..
0x0020:  00 fb 14 e9 14 e9 00 5a  d3 9d 00 00 00 00 00 03  .......Z ........
0x0030:  00 00 00 00 00 00 0f 5f  63 6f 6d 70 61 6e 69 6f  ......._ companio
0x0040:  6e 2d 6c 69 6e 6b 04 5f  74 63 70 05 6c 6f 63 61  n-link._ tcp.loca
0x0050:  6c 00 00 0c 00 01 07 5f  72 64 6c 69 6e 6b c0 1c  l......_ rdlink..
0x0060:  00 0c 00 01 0c 5f 73 6c  65 65 70 2d 70 72 6f 78  ....._sl eep-prox
0x0070:  79 04 5f 75 64 70 c0 21  00 0c 00 01              y._udp.! ....
```

```
aladix@aladix-Aspire:~/Desktop/sniffer$ sudo ./ipk-sniffer -i wlp3s0 --tcp --udp --icmp4 --icmp6 --arp --ndp --igmp --mld
timestamp: 2024-04-22T17:15:38+02:00
src MAC: 20:2b:20:d3:76:0b
dst MAC: 02:10:18:ea:50:7c
frame length: 315 bytes
src IP: 192.168.0.218
dst IP: 34.237.73.95
src port: 51476
dst port: 443
Protocol: TCP 

0x0000:  02 10 18 ea 50 7c 20 2b  20 d3 76 0b 08 00 45 00  ....P| +  .v...E.
0x0010:  01 2d 4d c0 40 00 40 06  be 3c c0 a8 00 da 22 ed  .-M.@.@. .<....".
0x0020:  49 5f c9 14 01 bb 2f 1c  ae d1 22 3a fd c7 80 18  I_..../. ..":....
0x0030:  0c 03 13 03 00 00 01 01  08 0a 5c bc f6 f5 20 7f  ........ ..\... .
0x0040:  40 4b 17 03 03 00 f4 00  00 00 00 00 00 05 eb f7  @K...... ........
0x0050:  83 28 39 91 99 6f f2 86  c1 af 6c e4 ef 82 ba 91  .(9..o.. ..l.....
0x0060:  30 2d 12 2d 0f 75 aa da  6a d9 10 b9 ec 44 93 f0  0-.-.u.. j....D..
0x0070:  04 c9 39 8f b2 c4 43 51  22 62 71 fa 8e 1a f4 c9  ..9...CQ "bq.....
0x0080:  e8 a9 8b 40 6d 25 34 04  94 62 82 e5 ad 70 65 c9  ...@m%4. .b...pe.
0x0090:  69 97 14 67 10 14 d0 74  2b 04 4e cd 61 40 cf f2  i..g...t +.N.a@..
0x00a0:  b4 14 25 03 b6 fc ee 08  9c 10 d3 26 cb 3c 54 5e  ..%..... ...&.<T^
0x00b0:  2d 75 4f 3e 60 11 90 96  02 27 2f c3 a9 f1 8a b9  -uO>`... .'/.....
0x00c0:  1e fa c8 fa 7a 5e 95 66  04 54 79 37 41 de 1a b6  ....z^.f .Ty7A...
0x00d0:  a5 dd 06 7d f7 e1 8b 02  b1 39 33 a2 95 a0 5a bf  ...}.... .93...Z.
0x00e0:  4b bd bd d0 9b f1 ac 28  72 14 5e c8 07 01 99 d2  K......( r.^.....
0x00f0:  c6 99 f3 0f 59 1e 83 3d  03 03 a8 31 67 10 e1 b0  ....Y..= ...1g...
0x0100:  ce 7a e3 1e b2 54 09 f6  90 7f 22 ea 61 3c 99 ac  .z...T.. ..".a<..
0x0110:  bd 46 20 74 6a 61 11 75  09 0f 52 7a f8 e6 86 ca  .F tja.u ..Rz....
0x0120:  32 40 04 3f 6d 6b 2b d9  7a 5f d7 97 c6 71 fd 68  2@.?mk+. z_...q.h
0x0130:  d3 66 ac dc 76 83 3a 3d  d3 e5 c3                 .f..v.:= ...
```

```
aladix@aladix-Aspire:~/Desktop/sniffer$ sudo ./ipk-sniffer -i wlp3s0 -p 443
[sudo] password for aladix: 
timestamp: 2024-04-22T17:39:38+02:00
src MAC: 02:10:18:ea:50:7c
dst MAC: 20:2b:20:d3:76:0b
frame length: 334 bytes
src IP: 162.159.133.234
dst IP: 192.168.0.218
src port: 443
dst port: 54590
Protocol: TCP 

0x0000:  20 2b 20 d3 76 0b 02 10  18 ea 50 7c 08 00 45 00   + .v... ..P|..E.
0x0010:  01 40 f4 45 40 00 3b 06  60 66 a2 9f 85 ea c0 a8  .@.E@.;. `f......
0x0020:  00 da 01 bb d5 3e 70 7e  8f ee 02 70 db 3f 80 18  .....>p~ ...p.?..
0x0030:  00 08 04 73 00 00 01 01  08 0a d5 ff 0b 72 ec 61  ...s.... .....r.a
0x0040:  ab 61 17 03 03 01 07 68  7d cd 73 d2 60 c1 1a 6b  .a.....h }.s.`..k
0x0050:  ec d1 90 e1 11 d1 3c 5c  56 58 60 32 e0 06 bf d8  ......<\ VX`2....
0x0060:  96 cc da 0f 2d f3 f2 d9  46 35 3a 2a 2d 15 b8 18  ....-... F5:*-...
0x0070:  56 a3 b1 10 38 52 22 88  5d b8 28 15 6e 82 91 2d  V...8R". ].(.n..-
0x0080:  aa 8f dc 02 c6 30 f5 26  da 10 65 d0 ea 8b 8c 9e  .....0.& ..e.....
0x0090:  47 ea 4f 25 7d f0 30 0f  a3 ae c2 7e 13 9d a8 ba  G.O%}.0. ...~....
0x00a0:  3d 2f 07 37 ab 68 4e d6  21 d2 33 9c 2e da 41 9f  =/.7.hN. !.3...A.
0x00b0:  2b c2 47 d2 65 05 0b de  26 33 2d b0 98 85 86 5e  +.G.e... &3-....^
0x00c0:  62 12 59 a3 6b 32 35 40  b9 42 c3 76 05 6c a9 91  b.Y.k25@ .B.v.l..
0x00d0:  5a 3a be f3 8d b7 78 77  73 bd e6 c5 9a e9 df 6b  Z:....xw s......k
0x00e0:  23 0f 69 15 70 70 f4 a7  f0 50 60 eb b8 44 0d ff  #.i.pp.. .P`..D..
0x00f0:  a5 36 84 0c ec ea 80 bd  d9 c9 95 47 7e be 5d af  .6...... ...G~.].
0x0100:  ee 3a ca 86 91 e6 60 3b  de 7f be 83 8f 88 d4 97  .:....`; ........
0x0110:  46 5b 2b 8a 1d e6 b6 9a  3c 99 4c cb ea 9d c8 b2  F[+..... <.L.....
0x0120:  62 74 e2 45 97 4c 07 fd  a2 25 ce 4f 0d 11 c0 c7  bt.E.L.. .%.O....
0x0130:  66 dc e5 35 af ee 6f 92  f2 3c ec a6 b6 03 fc 86  f..5..o. .<......
0x0140:  97 c3 b1 4e b2 fc d0 10  8d d0 a9 0f 54 04        ...N.... ....T.
```

```
aladix@aladix-Aspire:~/Desktop/sniffer$ sudo ./ipk-sniffer -i wlp3s0 --arp
timestamp: 2024-04-22T17:41:12+02:00
src MAC: 02:10:18:ea:50:7c
dst MAC: 20:2b:20:d3:76:0b
frame length: 60 bytes
src IP: 192.168.0.1
dst IP: 192.168.0.218
Protocol: ARP 

0x0000:  20 2b 20 d3 76 0b 02 10  18 ea 50 7c 08 06 00 01   + .v... ..P|....
0x0010:  08 00 06 04 00 01 02 10  18 ea 50 7c c0 a8 00 01  ........ ..P|....
0x0020:  00 00 00 00 00 00 c0 a8  00 da 00 00 00 00 00 00  ........ ........
0x0030:  00 00 00 00 00 00 00 00  00 00 00 00              ........ ....
```

```
aladix@aladix-Aspire:~/Desktop/sniffer$ sudo ./ipk-sniffer -i wlp3s0 --ndp
timestamp: 2024-04-22T17:41:59+02:00
src MAC: 20:2b:20:d3:76:0b
dst MAC: 02:10:18:ea:50:7c
frame length: 86 bytes
src IP: fe80::2dc3:4655:bd1f:2caa
dst IP: fe80::10:18ff:feea:507c
Cieľová adresa NDP: fe80::10:18ff:feea:507c

0x0000:  02 10 18 ea 50 7c 20 2b  20 d3 76 0b 86 dd 60 00  ....P| +  .v...`.
0x0010:  00 00 00 20 3a ff fe 80  00 00 00 00 00 00 2d c3  ... :... ......-.
0x0020:  46 55 bd 1f 2c aa fe 80  00 00 00 00 00 00 00 10  FU..,... ........
0x0030:  18 ff fe ea 50 7c 87 00  96 48 00 00 00 00 fe 80  ....P|.. .H......
0x0040:  00 00 00 00 00 00 00 10  18 ff fe ea 50 7c 01 01  ........ ....P|..
0x0050:  20 2b 20 d3 76 0b                                  + .v.
```

```
aladix@aladix-Aspire:~/Desktop/sniffer$ sudo ./ipk-sniffer -i wlp3s0 --icmp6
timestamp: 2024-04-22T17:43:09+02:00
src MAC: 20:2b:20:d3:76:0b
dst MAC: 02:10:18:ea:50:7c
frame length: 86 bytes
src IP: fe80::2dc3:4655:bd1f:2caa
dst IP: fe80::10:18ff:feea:507c
src IP: 0:100:406:202b:20d3:760b::
dst IP: ::
Type: 135, Code: 0
Protocol: ICMPv6

0x0000:  02 10 18 ea 50 7c 20 2b  20 d3 76 0b 86 dd 60 00  ....P| +  .v...`.
0x0010:  00 00 00 20 3a ff fe 80  00 00 00 00 00 00 2d c3  ... :... ......-.
0x0020:  46 55 bd 1f 2c aa fe 80  00 00 00 00 00 00 00 10  FU..,... ........
0x0030:  18 ff fe ea 50 7c 87 00  96 48 00 00 00 00 fe 80  ....P|.. .H......
0x0040:  00 00 00 00 00 00 00 10  18 ff fe ea 50 7c 01 01  ........ ....P|..
0x0050:  20 2b 20 d3 76 0b                                  + .v.
```