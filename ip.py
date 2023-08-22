from iputils import *
from ipaddress import ip_address, ip_network
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []
        self.identification = 0  # Adicionando o atributo identification e inicializando-o como 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # Atuando como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Roteador
            vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr, dest_addr = struct.unpack('!BBHHHBBHII', datagrama[:20])
            
            # Decrementa TTL
            ttl -= 1
            
            if ttl == 0:
                # TTL expirou, enviar mensagem ICMP de tempo excedido
                typ = 11
                code = 0
                checksum_icmp = calc_checksum(struct.pack('!BBHI', typ, code, 0, 0) + datagrama[:28])
                icmp = struct.pack('!BBHI', typ, code, checksum_icmp, 0) + datagrama[:28]
                addr_int = int.from_bytes(str2addr(self.meu_endereco), "big")
                checksum = calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, 20 + len(icmp), identification, flagsfrag, 64, 1, 0, addr_int, src_addr))
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, 20 + len(icmp), identification, flagsfrag, 64, 1, checksum, addr_int, src_addr) + icmp
                self.identification += 1
                next_hop = self._next_hop(src_addr)
            else:
                # Atualiza checksum e envia datagrama
                checksum = 0  # Zera o checksum para recalcular
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr, dest_addr) + datagrama[20:]
                checksum = calc_checksum(datagrama)
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr, dest_addr) + datagrama[20:]
                next_hop = self._next_hop(dest_addr)
            
            self.enlace.enviar(datagrama, next_hop)



    def _next_hop(self, dest_addr):
        matched_network = None
        matched_prefix_length = -1

        for cidr, next_hop in self.tabela:
            network = ip_network(cidr)
            if ip_address(dest_addr) in network:
                prefix_length = network.prefixlen
                if prefix_length > matched_prefix_length:
                    matched_network = next_hop
                    matched_prefix_length = prefix_length

        return matched_network

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)

        # Cabeçalho IP
        version_ihl = 69  # Versão 4 (IPv4) e Internet Header Length (5 palavras de 32 bits, 20 bytes)
        dscp_ecn = 0  # DSCP (Differentiated Services Code Point) e ECN (Explicit Congestion Notification) - não usaremos diferenciação de serviços ou notificação de congestão
        total_len = 20 + len(segmento)  # Tamanho total do datagrama (20 bytes do cabeçalho IP + tamanho do segmento)
        identification = self.identification  # Número de identificação do datagrama
        flags_frag = 0  # Flags e deslocamento de fragmento (não usaremos fragmentação)
        ttl = 64  # Time-to-Live (tempo de vida) do datagrama
        proto = IPPROTO_TCP  # Protocolo TCP
        checksum = 0  # O checksum será calculado posteriormente
        src_addr = str2addr(self.meu_endereco)  # Endereço IP de origem (convertemos para o formato inteiro)
        dest_addr = str2addr(dest_addr)  # Endereço IP de destino (convertemos para o formato inteiro)

        # Montando o cabeçalho IP
        header = struct.pack('!BBHHHBBH', version_ihl, dscp_ecn, total_len, identification, flags_frag, ttl, proto, checksum) + src_addr + dest_addr

        # Calculando o checksum do cabeçalho IP (campo checksum inicializado com 0)
        checksum = calc_checksum(header)
        header = struct.pack('!BBHHHBBH', version_ihl, dscp_ecn, total_len, identification, flags_frag, ttl, proto, checksum) + src_addr + dest_addr

        # Montando o datagrama completo (cabeçalho IP + payload)
        datagrama = header + segmento

        # Enviando o datagrama para o próximo salto (next_hop)
        self.enlace.enviar(datagrama, next_hop)

        # Incrementando o número de identificação do datagrama para o próximo envio
        self.identification += 1
