import struct
import unittest
from elf_page_permissions import inspect,example

def fixture(cls,order):
 e='<' if order==1 else '>';size=52 if cls==1 else 64;ps=32 if cls==1 else 56;length=size+ps
 ident=b'\x7fELF'+bytes([cls,order,1])+bytes(9)
 h=struct.pack(e+('HHIIIIIHHHHHH' if cls==1 else 'HHIQQQIHHHHHH'),2,3,1,0x1000,size,0,0,size,ps,1,0,0,0)
 p=struct.pack(e+('IIIIIIII' if cls==1 else 'IIQQQQQQ'),*( [1,0,0x1000,0,length,length,5,1] if cls==1 else [1,5,0,0x1000,0,length,length,1]))
 return ident+h+p
class Behavior(unittest.TestCase):
 def test_classes_endian(self):
  for c in (1,2):
   for e in (1,2):
    r=inspect(fixture(c,e));self.assertEqual(r['class_bits'],32 if c==1 else 64);self.assertEqual(r['findings'],[])
 def test_union_and_bss(self):
  r=inspect(example());self.assertEqual(r['page_intervals'][0]['flags_union'],7);self.assertEqual(r['loads'][1]['zero_fill_range'],[0x400100,0x400200]);self.assertEqual(len(r['findings']),1)
 def test_overlap(self):
  b=bytearray(example());struct.pack_into('<Q',b,120+16,0x400080)
  self.assertTrue(any(f['kind']=='ambiguous_LOAD_overlap' for f in inspect(b)['findings']))
 def test_entry_outside(self):
  b=bytearray(example());struct.pack_into('<Q',b,24,0)
  self.assertTrue(any(f['kind']=='entry_outside_executable_LOAD' for f in inspect(b)['findings']))
 def test_size_alignment(self):
  for where,value in ((64+32,1000),(64+40,1),(64+48,3)):
   b=bytearray(example());struct.pack_into('<Q',b,where,value)
   with self.assertRaises(ValueError):inspect(b)
 def test_page_size(self):
  for n in (0,513,131072):
   with self.assertRaises(ValueError):inspect(example(),n)
 def test_huge_virtual_range_no_page_allocation(self):
  b=bytearray(fixture(2,1));struct.pack_into('<Q',b,64+40,1<<50)
  self.assertEqual(len(inspect(b)['page_intervals']),1)
 def test_unsupported_and_truncated(self):
  b=bytearray(example());struct.pack_into('<H',b,16,1)
  for raw in (bytes(b),example()[:63],b'not ELF'):
   with self.assertRaises(ValueError):inspect(raw)
