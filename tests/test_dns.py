#-*- coding:utf-8 -*-
import os
import sys
import unittest

PWD = os.path.dirname(os.path.realpath(__file__))
FOLDER_PARENT = os.path.dirname(PWD)
sys.path.insert(0, FOLDER_PARENT)

import dns

class TestMessageUnpacker(unittest.TestCase):

    def test_it(self):
        reply = "\x00Z\x00\x00\x80\x80\x00\x01\x00\x03\x00\x00\x00\x00\x03www\x05baidu\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x02.\x00\x0f\x03www\x01a\x06shifen\xc0\x16\xc0+\x00\x01\x00\x01\x00\x00\x00\xc9\x00\x04:\xd9\xc8'\xc0+\x00\x01\x00\x01\x00\x00\x00\xc9\x00\x04:\xd9\xc8%"

        msg_unpacker = dns.MessageUnpacker(s=reply[2:])
        dns.HelperMessageUnpacker.get_and_print_header(msg_unpacker)
        self.assertEqual(dns.HelperBitwise.unpack16bit(reply[:2]), 90)

if __name__ == '__main__':
    unittest.main()