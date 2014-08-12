

class Helper(object):

    @staticmethod
    def read_until(sock, until):
        data = ''
        while data.find(until) == -1:
            buf = sock.recv(1)
            if not buf:
                break
            data += buf
        return data

    @staticmethod
    def recv_all(sock, size):
        chunks = []
        total = size
        while total > 0:
            chunk = sock.recv(total)
            chunks.append(chunk)
            total -= len(chunk)
        return ''.join(chunks)

    @staticmethod
    def get_header_value_by_name(lines, name):
        for line in lines:
            line = line.lower()
            if line.find(name.lower()) != -1:
                return line[line.index(':') + 1:].strip()
        return