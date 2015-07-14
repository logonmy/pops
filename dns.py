"""
RFC 1035 - Domain names - implementation and specification

References
 - http://tools.ietf.org/html/rfc1035
 - https://technet.microsoft.com/en-us/library/dd197470(v=ws.10).aspx

See also
 - http://svn.python.org/projects/python/tags/r15a1/Demo/dns/
 - https://github.com/paulchakravarti/dnslib
 - http://people.omnigroup.com/wiml/soft/rfc1035.py
"""
import socket
import sys


LABEL_MAX_LEN = 63
NAME_MAX_LEN = 255
UDP_MSG_MAX_LEN = 512
RDATA_MAX_LEN = 65535
TCP_MSG_MAX_LEN = 65535  # two byte

NS_SERVER = "114.114.114.114"
NS_PORT = 53


class ConstToStr:

    @classmethod
    def const_to_str(cls, c):
        const_str_map = {}
        for name in dir(cls):
            if not name.startswith('_') and name != 'const_to_str':
                val = cls.__dict__[name]
                const_str_map[val] = name
        return const_str_map[c]


class Opcode(ConstToStr):
    # http://tools.ietf.org/html/rfc1035#section-4.1.1
    QUERY = 0  # a standard query
    IQUERY = 1  # an inverse query
    STATUS = 2  # a server status request


class TypeValue(ConstToStr):
    # http://tools.ietf.org/html/rfc1035#section-3.2.2
    A = 1  # a host address
    NS = 2  # an authoritative name server
    MD = 3  # a mail destination (Obsolete - use MX)
    MF = 4  # a mail forwarder (Obsolete - use MX)
    CNAME = 5  # the canonical name for an alias
    SOA = 6  # marks the start of a zone of authority
    MB = 7  # a mailbox domain name (EXPERIMENTAL)
    MG = 8  # a mail group member (EXPERIMENTAL)
    MR = 9  # a mail rename domain name (EXPERIMENTAL)
    NULL = 10  # a null RR (EXPERIMENTAL)
    WKS = 11  # a well known service description
    PTR = 12  # a domain name pointer
    HINFO = 13  # host information
    MINFO = 14  # mailbox or mail list information
    MX = 15  # mail exchange
    TXT = 16  # text strings

    # Additional TYPE values from host.c source
    UNAME = 110
    MP = 240

    # QTYPE values
    AXFR = 252  # A request for a transfer of an entire zone
    MAILB = 253  # A request for mailbox-related records (MB, MG or MR)
    MAILA = 254  # A request for mail agent RRs (Obsolete - see MX)
    ANY = 255  # A request for all records


class ClassValue(ConstToStr):
    # http://tools.ietf.org/html/rfc1035#section-3.2.4
    IN = 1  # the Internet
    CS = 2  # the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3  # the CHAOS class
    HS = 4  # Hesiod [Dyer 87]

    # QCLASS 
    ANY = 255  # any class


class RCodeValue(ConstToStr):
    NO_ERROR_CONDITION = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5


class QRValue(ConstToStr):
    QUERY = 0
    RESPONSE = 1


class HelperBitwise:
    @staticmethod
    def pack16bit(n):
        return chr((n >> 8) & 0xff) + \
               chr(n & 0xff)

    @staticmethod
    def pack32bit(n):
        return chr((n >> 24) & 0xff) + \
               chr((n >> 16) & 0xff) + \
               chr((n >> 8) & 0xff) + \
               chr((n) & 0xff)

    @staticmethod
    def unpack16bit(s):
        return (ord(s[0]) << 8) | \
               ord(s[1])

    @staticmethod
    def unpack32bit(s):
        return (ord(s[0]) << 24) | \
               (ord(s[1]) << 16) | \
               (ord(s[2]) << 8) | \
               (ord(s[3]))


class Packer(object):
    def __init__(self):
        self._buf = ''

    def get_buf(self):
        return self._buf

    def add_16bit(self, n):
        self._buf += HelperBitwise.pack16bit(n)

    def add_32bit(self, n):
        self._buf += HelperBitwise.pack32bit(n)

    def add_name(self, s):
        buff = []

        for label in s.split('.'):
            if len(label) > LABEL_MAX_LEN:
                raise Exception('label too long')

            item = chr(len(label)) + label
            buff.append(item)

        self._buf += ''.join(buff) + '\0'


class Unpacker(object):
    def __init__(self, s):
        self._buf = s
        self._offset = 0

    def get_bytes(self, n):
        s = self._buf[self._offset: self._offset + n]
        self._offset += n
        return s

    def get_16bit(self):
        n = HelperBitwise.unpack16bit(self.get_bytes(2))
        return n

    def get_32bit(self):
        n = HelperBitwise.unpack32bit(self.get_bytes(4))
        return n

    def get_name(self):
        """
        Domain name unpacking
        """
        n = ord(self.get_bytes(n=1)) # The max length of domain name is NAME_MAX_LEN, we use ord here.

        """
        The pointer takes the form of a two octet sequence:

                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        | 1 1|                OFFSET                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        0xC0
         1100 0000

        0xC000
         1100 0000 0000 0000
        """

        is_pointer = n & 0xC0 == 0xC0

        if is_pointer:
            next_len = ord(self.get_bytes(n=1))
            pointer = ((n << 8) | next_len) & ~0xC000
            save_offset = self._offset

            try:
                self._offset = pointer
                domain_name = self.get_name()
            finally:
                self._offset = save_offset
            return domain_name
        elif n == 0:
            return ''

        domain_name = self.get_bytes(n=n)
        remains = self.get_name()
        s = domain_name
        if remains:
            s = domain_name + '.' + remains
        return s

    def get_str(self):
        data_len = ord(self.get_bytes(n=1))
        return self.get_bytes(n=data_len)

    def get_addr(self):
        bin2addr = lambda n: '%d.%d.%d.%d' % (
            (n >> 24) & 0xFF,
            (n >> 16) & 0xFF,
            (n >> 8) & 0xFF,
            n & 0xFF,
        )
        return bin2addr(self.get_32bit())


class ResourceRecordUnpacker(Unpacker):

    def __init__(self, **kwargs):
        super(ResourceRecordUnpacker, self).__init__(**kwargs)
        self._rd_end = None

    def get_rr_header(self):
        """
        RR(Resource Record) format
                                            1  1  1  1  1  1
              0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                                               |
            /                                               /
            /                      NAME                     /
            |                                               |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TYPE                     |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     CLASS                     |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TTL                      |
            |                                               |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                   RDLENGTH                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
            /                     RDATA                     /
            /                                               /
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        """
        name = self.get_name()
        _type = self.get_16bit()
        _class = self.get_16bit()
        ttl = self.get_32bit()
        rdlength = self.get_16bit()

        if rdlength > RDATA_MAX_LEN:
            raise Exception('rdata too long')

        self._rd_end = self._offset + rdlength

        return name, _type, _class, ttl, rdlength

    def get_data_cname(self):
        return self.get_name()

    def get_data_hinfo(self):
        return self.get_str(), self.get_str()

    def get_data_mx(self):
        return self.get_16bit(), self.get_name()

    def get_data_ns(self):
        return self.get_name()

    def get_data_ptr(self):
        return self.get_name()

    def get_data_soa(self):
        return self.get_name(), \
               self.get_name(), \
               self.get_32bit(), \
            self.get_32bit(), \
            self.get_32bit(), \
            self.get_32bit(), \
            self.get_32bit()

    def get_data_txt(self):
        items = []
        while self._offset != self._rd_end:
            items.append(self.get_str())
        return items

    def get_data_a(self):
        return self.get_addr()

    def get_data_wks(self):
        address = self.get_addr()
        protocol = ord(self.get_bytes(n=1))

        n = self._rd_end - self._offset
        bitmap = self.get_bytes(n=n)

        return address, protocol, bitmap


class HelperMessageUnpacker:

    @staticmethod
    def get_and_print_resource_record(msg_unpacker):
        name, _type, _class, ttl, rdlength = msg_unpacker.get_rr_header()
        _type_str = TypeValue.const_to_str(_type)

        func_name = 'get_data_%s' % _type_str.lower()
        if hasattr(msg_unpacker, func_name):
            func = getattr(msg_unpacker, func_name)
            rdata = func()
        else:
            rdata = msg_unpacker.get_bytes(rdlength)

        print "name={name} " \
              "type={_type}({_type_str}) " \
              "class={_class}({_class_str}) " \
              "ttl={ttl} " \
              "rdlength={rdlength} " \
              "rdata={rdata}".format(
            name=name,
            _type=_type,
            _class=_class,
            ttl=ttl,
            rdlength=rdlength,
            rdata=rdata,

            _type_str=_type_str,
            _class_str=ClassValue.const_to_str(_class),
        )

    @staticmethod
    def get_and_print_question(msg_unpacker):
        qname, qtype, qclass = msg_unpacker.get_question()
        print "qname={qname} " \
              "qtype={qtype}({qtype_str}) " \
              "qclass={qclass}({qclass_str})".format(
            qname=qname,
            qtype=qtype,
            qclass=qclass,

            qtype_str=TypeValue.const_to_str(qtype),
            qclass_str=ClassValue.const_to_str(qclass),
        )

    @staticmethod
    def get_and_print_header(msg_unpacker):
        _id, \
        qr, \
        opcode, \
        aa, \
        tc, \
        rd, \
        ra, \
        z, \
        rcode, \
        qdcount, \
        ancount, \
        nscount, \
        arcount = msg_unpacker.get_header()

        print ">>> Header"
        print "id={_id} " \
              "qr={qr}({qr_str}) " \
              "opcode={opcode}({opcode_str}) " \
              "aa={aa} " \
              "tc={tc} " \
              "rd={rd} " \
              "ra={ra} " \
              "z={z} " \
              "rcode={rcode}({rcode_str}) " \
              "qdcount={qdcount} " \
              "ancount={ancount} " \
              "nscount={nscount} " \
              "arcount={arcount}".format(
            _id=_id,
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            z=z,
            rcode=rcode,
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,

            qr_str=QRValue.const_to_str(qr),
            opcode_str=QRValue.const_to_str(opcode),
            rcode_str=RCodeValue.const_to_str(rcode),
        )

        if rcode != RCodeValue.NO_ERROR_CONDITION:
            raise Exception("got unexpected rcode %d(%s)" % (rcode, RCodeValue.const_to_str(rcode)))

        if qdcount:
            print ">>> Question"
            for i in range(qdcount):
                HelperMessageUnpacker.get_and_print_question(msg_unpacker)

        if ancount:
            print ">>> Answer"
            for i in range(ancount):
                HelperMessageUnpacker.get_and_print_resource_record(msg_unpacker)

        if nscount:
            print ">>> Authority"
            for i in range(nscount):
                HelperMessageUnpacker.get_and_print_resource_record(msg_unpacker)

        if arcount:
            print ">>> Additional"
            for i in range(arcount):
                HelperMessageUnpacker.get_and_print_resource_record(msg_unpacker)



class MessagePacker(Packer):
    """
    Message format

        +---------------------+
        |        Header       |
        +---------------------+
        |       Question      | the question for the name server
        +---------------------+
        |        Answer       | RRs answering the question
        +---------------------+
        |      Authority      | RRs pointing toward an authority
        +---------------------+
        |      Additional     | RRs holding additional information
        +---------------------+
    """

    def set_header(
            self,
            _id=0,  # query ID
            qr=QRValue.QUERY,  # Query or Response
            opcode=Opcode.QUERY,  # query kind
            aa=0,  # Authoritative Answer
            tc=0,  # TrunCation

            rd=0,  # Recursion Desired
            ra=0,  # Recursion Available
            z=0,  # reserved
            rcode=0,  # Response Code

            qdcount=1, # number of entries in the question section
            ancount=0, # number of resource records in the ANswer section
            nscount=0, # number of Name Server resource records in the question section
            arcount=0):  # number of resource records in the Additional Records section
        """
        Header section format

                                            1  1  1  1  1  1
              0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      ID                       |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    QDCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    ANCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    NSCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    ARCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        """
        self.add_16bit(_id)

        # 4 bits is 2**4 => 0xF
        # why `z` not uses `0x8` to test it?
        val = (qr & 1) << 15 | \
              (opcode & 0xF) << 11 | \
              (aa & 1) << 10 | \
              (tc & 1) << 9 | \
              (rd & 1) << 8 | \
              (ra & 1) << 7 | \
              (z & 0x7) << 4 | \
              (rcode & 0xF)

        self.add_16bit(val)
        self.add_16bit(qdcount)
        self.add_16bit(ancount)
        self.add_16bit(nscount)
        self.add_16bit(arcount)

    def set_question(self, qname, qtype, qclass):
        """
        Question section format
                                            1  1  1  1  1  1
              0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                                               |
            /                     QNAME                     /
            /                                               /
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     QTYPE                     |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     QCLASS                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        """

        self.add_name(qname)
        self.add_16bit(qtype)
        self.add_16bit(qclass)


class QuestionUnpacker(Unpacker):

    def get_question(self):
        qname = self.get_name()
        qtype = self.get_16bit()
        qclass = self.get_16bit()

        return qname, qtype, qclass


class MessageUnpacker(ResourceRecordUnpacker, QuestionUnpacker):

    def get_header(self):
        _id = self.get_16bit()

        flags = self.get_16bit()

        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF # 4 bits is 2**4 => 0xF
        aa = (flags >> 10) & 1
        tc = (flags >> 9) & 1
        rd = (flags >> 8) & 1

        ra = (flags >> 7) & 1
        z = (flags >> 4) & 0x7 # why `z` not uses `0x8` to test it?
        rcode = flags & 0xF

        qdcount = self.get_16bit()
        ancount = self.get_16bit()
        nscount = self.get_16bit()
        arcount = self.get_16bit()

        return _id, \
               qr, \
               opcode, \
               aa, \
               tc, \
               rd, \
               ra, \
               z, \
               rcode, \
               qdcount, \
               ancount, \
               nscount, \
               arcount


class MessageResponseParser(object):

    def __init__(self, domain_name, s):
        self.domain_name = domain_name
        self.ip_address_list = []

        msg_unpacker = MessageUnpacker(s=s)

        _id, \
        qr, \
        opcode, \
        aa, \
        tc, \
        rd, \
        ra, \
        z, \
        rcode, \
        qdcount, \
        ancount, \
        nscount, \
        arcount = msg_unpacker.get_header()

        if rcode != RCodeValue.NO_ERROR_CONDITION:
            raise Exception("got unexpected rcode %d(%s)" % (rcode, RCodeValue.const_to_str(rcode)))

        if qdcount:
            for i in range(qdcount):
                qname, qtype, qclass = msg_unpacker.get_question()

        if ancount:
            for i in range(ancount):
                name, _type, _class, ttl, rdlength, rdata = MessageResponseParser.parse_rr(msg_unpacker)

                if _type == TypeValue.A:
                    self.ip_address_list.append(rdata)

        if nscount:
            for i in range(nscount):
                name, _type, _class, ttl, rdlength, rdata = MessageResponseParser.parse_rr(msg_unpacker)

        if arcount:
            for i in range(arcount):
                name, _type, _class, ttl, rdlength, rdata = MessageResponseParser.parse_rr(msg_unpacker)

    @staticmethod
    def parse_rr(msg_unpacker):
        name, _type, _class, ttl, rdlength = msg_unpacker.get_rr_header()
        _type_str = TypeValue.const_to_str(_type)

        func_name = 'get_data_%s' % _type_str.lower()
        if hasattr(msg_unpacker, func_name):
            func = getattr(msg_unpacker, func_name)
            rdata = func()
        else:
            rdata = msg_unpacker.get_bytes(rdlength)

        return name, _type, _class, ttl, rdlength, rdata



def gethostbyname(name, ns_server=NS_SERVER, ns_port=NS_PORT):
    mp = MessagePacker()
    mp.set_header()
    mp.set_question(qname=name, qtype=TypeValue.A, qclass=ClassValue.IN)
    msg_req = mp.get_buf()
    data = HelperBitwise.pack16bit(len(msg_req)) + msg_req

    if len(data) > TCP_MSG_MAX_LEN:
        raise Exception('TCP message too long')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ns_server, ns_port))
    sock.sendall(data)
    sock.shutdown(socket.SHUT_WR)

    fi = sock.makefile('r')

    field_len = fi.read(2)
    if len(field_len) < 2:
        raise Exception("got invalid response")

    msg_len = HelperBitwise.unpack16bit(field_len)

    reply = fi.read(msg_len)
    if len(reply) != msg_len:
        raise Exception("got incomplete response")

    parser = MessageResponseParser(domain_name=name, s=reply)
    return parser.ip_address_list

def main(name):
    mp = MessagePacker()
    mp.set_header()
    mp.set_question(qname=name, qtype=TypeValue.A, qclass=ClassValue.IN)
    msg_req = mp.get_buf()
    data = HelperBitwise.pack16bit(len(msg_req)) + msg_req

    if len(data) > TCP_MSG_MAX_LEN:
        raise Exception('TCP message too long')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((NS_SERVER, NS_PORT))
    sock.sendall(data)
    sock.shutdown(socket.SHUT_WR)

    fi = sock.makefile('r')

    field_len = fi.read(2)
    if len(field_len) < 2:
        print ">>> EOF"
        return

    msg_len = HelperBitwise.unpack16bit(field_len)

    reply = fi.read(msg_len)
    if len(reply) != msg_len:
        print ">>> incomplete reply"
        return

    msg_unpacker = MessageUnpacker(s=reply)
    HelperMessageUnpacker.get_and_print_header(msg_unpacker)

if __name__ == '__main__':
    args = sys.argv[1:]
    if not args:
        print "Usage: %s name..."
    else:
        for name in args:
            main(name)

    sys.exit(0)
