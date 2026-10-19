"""Offline ELF LOAD range and declared page-permission-union evidence."""
import argparse
import hashlib
import json
import struct
import sys


def inspect(raw,page_size=4096):
    if type(page_size) is not int or not 512<=page_size<=65536 or page_size&(page_size-1):raise ValueError('page size must be power of two in 512..65536')
    if len(raw)>8388608 or len(raw)<16 or raw[:4]!=b'\x7fELF':raise ValueError('ELF file required, at most 8 MiB')
    cls,order,version=raw[4:7]
    if cls not in (1,2) or order not in (1,2) or version!=1:raise ValueError('unsupported ELF identification')
    endian='<' if order==1 else '>';fmt=endian+('HHIIIIIHHHHHH' if cls==1 else 'HHIQQQIHHHHHH')
    size=52 if cls==1 else 64;phsize=32 if cls==1 else 56
    if len(raw)<size:raise ValueError('truncated ELF header')
    h=struct.unpack_from(fmt,raw,16)
    typ,machine,ver,entry,phoff,shoff,flags,ehsize,phentsize,phnum,*_=h
    if typ not in (2,3) or ver!=1 or ehsize!=size or phentsize!=phsize or not 1<=phnum<=128:
        raise ValueError('only EXEC/DYN with standard headers and 1..128 program headers')
    if phoff<size or phoff+phnum*phsize>len(raw):raise ValueError('program header table outside file')
    loads=[];findings=[];stack=[];interps=[];limit=1<<(32 if cls==1 else 64)
    for i in range(phnum):
        t=struct.unpack_from(endian+('IIIIIIII' if cls==1 else 'IIQQQQQQ'),raw,phoff+i*phsize)
        if cls==1:kind,offset,vaddr,paddr,filesz,memsz,perm,align=t
        else:kind,perm,offset,vaddr,paddr,filesz,memsz,align=t
        if kind not in (1,3,0x6474e551):continue
        if offset+filesz>len(raw) or vaddr+memsz>limit:raise ValueError('segment outside supported bounds')
        if kind==1:
            if filesz>memsz or perm&~7 or (align>1 and (align&(align-1) or vaddr%align!=offset%align)):
                raise ValueError('invalid LOAD sizes, flags or alignment')
            if vaddr%page_size!=offset%page_size:findings.append({'kind':'page_offset_incongruence','segment':i})
            loads.append({'index':i,'flags':perm,'file_range':[offset,offset+filesz],
                          'virtual_range':[vaddr,vaddr+memsz],'zero_fill_range':[vaddr+filesz,vaddr+memsz]})
            if perm&3==3:findings.append({'kind':'writable_executable_segment','segment':i})
        elif kind==0x6474e551:
            stack.append(perm)
            if perm&3==3:findings.append({'kind':'writable_executable_stack','segment':i})
        else:
            b=raw[offset:offset+filesz]
            if not 1<=len(b)<=4096 or b[-1:]!=b'\0' or b'\0' in b[:-1]:raise ValueError('invalid interpreter string')
            try:interps.append(b[:-1].decode('ascii'))
            except UnicodeError:raise ValueError('non-ASCII interpreter unsupported') from None
    if not loads:raise ValueError('no LOAD segments')
    ranges=[]
    for l in loads:
        lo,hi=l['virtual_range']
        if hi>lo:ranges.append((lo//page_size*page_size,(hi+page_size-1)//page_size*page_size,l))
    points=sorted({p for lo,hi,l in ranges for p in (lo,hi)});pages=[]
    for lo,hi in zip(points,points[1:]):
        owners=[l for a,b,l in ranges if a<=lo and hi<=b]
        if not owners:continue
        perm=0
        for l in owners:perm|=l['flags']
        pages.append({'range':[lo,hi],'flags_union':perm,'segments':[l['index'] for l in owners]})
        if perm&3==3:findings.append({'kind':'writable_executable_page_union','range':[lo,hi]})
    for i,a in enumerate(loads):
        for b in loads[i+1:]:
            lo=max(a['virtual_range'][0],b['virtual_range'][0]);hi=min(a['virtual_range'][1],b['virtual_range'][1])
            if lo<hi:findings.append({'kind':'ambiguous_LOAD_overlap','segments':[a['index'],b['index']],'range':[lo,hi]})
    if not any(l['flags']&1 and l['virtual_range'][0]<=entry<l['virtual_range'][1] for l in loads):
        findings.append({'kind':'entry_outside_executable_LOAD','entry':entry})
    return {'sha256':hashlib.sha256(raw).hexdigest(),'class_bits':32 if cls==1 else 64,'byte_order':order,
            'type':typ,'machine':machine,'entry':entry,'page_size':page_size,'loads':loads,'page_intervals':pages,
            'stack_flags':stack if stack else 'unknown: GNU_STACK absent','interpreters_not_executed':interps,'findings':findings}


def example():
    ident=b'\x7fELF'+bytes([2,1,1])+bytes(9)
    h=struct.pack('<HHIQQQIHHHHHH',2,62,1,0x400080,64,0,0,64,56,2,0,0,0)
    a=struct.pack('<IIQQQQQQ',1,5,0,0x400000,0,176,256,1)
    b=struct.pack('<IIQQQQQQ',1,6,256,0x400100,0,0,256,1)
    return (ident+h+a+b).ljust(256,b'\0')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input',nargs='?');p.add_argument('--make-example');p.add_argument('--page-size',type=int,default=4096);a=p.parse_args()
    try:
        if bool(a.input)==bool(a.make_example):raise ValueError('specify input OR --make-example NEW_FILE')
        if a.make_example:
            with open(a.make_example,'xb') as f:f.write(example())
            return 0
        with open(a.input,'rb') as f:raw=f.read(8388609)
        r=inspect(raw,a.page_size);print(json.dumps(r,indent=2));return int(bool(r['findings']))
    except (ValueError,OSError,struct.error) as e:print(str(e),file=sys.stderr);return 2


if __name__=='__main__':sys.exit(main())
