#!/usr/bin/python
import sys,os

#This wraps the kernel symbol table.
class Sym_Table(object):
    def __init__(self,f,dbg_out=True):
        #sym_table: addr --> (type,name,size)
        self._sym_table = {}
        #r_sym_table: name --> list of (type,addr,size)
        self._r_sym_table = {}
        self.raw_syms = []
        #Fill the tables
        self._load_symbol_table(f)
        self.dbg_out = dbg_out

    #Load symbol table(s) from a file.
    def _load_symbol_table(self,f):
        with open(f,'r') as symf:
            s_buf=symf.readlines()
            for i in range(len(s_buf)):
                line=s_buf[i]
                line = line[:-1] if line[-1] == '\n' else line
                #Assume the format is "addr type name" 
                tokens = line.split(' ')
                (addr,ty,name) = (int(tokens[0],16),tokens[1],self._trim_func_name(tokens[2]))
                break
            self.raw_syms += [(addr,ty,name)]
            for i in range(1,len(s_buf)):
                line=s_buf[i]
                line = line[:-1] if line[-1] == '\n' else line
                tokens = line.split(' ')
                (n_addr,n_ty,n_name) = (int(tokens[0],16),tokens[1],self._trim_func_name(tokens[2]))
                size = n_addr - addr
                if size==0:
                    k=1
                    nn_addr=n_addr
                    while nn_addr==addr and i+k < len(s_buf):
                        nn_addr=int(s_buf[i+k].split(' ')[0],16)
                        k +=1
                    size = nn_addr-addr
                self._sym_table[addr] = (ty,name,size)
                self._r_sym_table.setdefault(name,[]).append((ty,addr,size))
                (addr,ty,name) = (n_addr,n_ty,n_name)
                self.raw_syms += [(addr,ty,name)]
            #Actually we still have one entry remained here, but I think we can ignore this in the case of linux kernel symbol table.
            #Since this is usually in '.bss' section

    #Sometimes we can see compiler added suffix in the function names, such as 'func.isra.XX', trim them.
    def _trim_func_name(self,name):
        suffix_list = ['isra','constprop']
        tokens = name.split('.')
        if len(tokens) > 1 and tokens[1] in suffix_list:
            return tokens[0]
        return name

    #The 'k' can be either symbol name or addr, return the information tuple.
    def lookup(self,k):
        if isinstance(k,int) or isinstance(k,long):
            return self._sym_table[k] if k in self._sym_table else None
        elif isinstance(k,str):
            return self._r_sym_table[k] if k in self._r_sym_table else None
        return None
    
    #Sometimes the funcname in symbol table is not the same as source code.(with additional string)
    def lookup_func_name_complete(self,n):
        func_list=[]
        for (addr,ty,name) in self.raw_syms:
            if name.startswith(n):
                func_list+= self._r_sym_table[name]
        return func_list 

    #This is specifically designed to pick one tuple for a function name.
    def lookup_func_name(self,n,mode=0):
        #specific cases:
        if 'SyS' in n:
            n=n.lower()
        func_list = self.lookup(n)
        if mode==1:
            print 'mode ==1!!'
            func_list = self.lookup_func_name_complete(n)
        (addr,size) = (0,0)
        if not func_list:
            return None
        func_list=[element for element in func_list if element[0] in ('T','t')]
        if not func_list:
            if self.dbg_out:
                print 'Cannot find function name in symbol table: ' , n
            return None
        #we prefer function with larger size
        func_list.sort(key=lambda x: x[2],reverse=True)
        if self.dbg_out:
            for (ty,addr,size) in func_list:
                print '[Func] %s: %x - %x' % (n,addr,addr + size)
        if mode==2:
            return func_list
        else:
            (ty,addr,size)=func_list[0] 
            return (ty,addr,size)

    def probe_arm64_kernel_base(self):
        for (addr,ty,name) in self.raw_syms:
            if addr >= 0xffff000000000000 and ty in ('T','t'):
                break
        print 'Probed image base address: %x' % addr
        return addr

    #Decide the code ('t'/'T') segments according to the symbol table file.
    #The base is the memory load base address of the image.
    def get_code_segments(self,base):
        prev_st = None
        segments = []
        for (addr,ty,name) in self.raw_syms:
            if addr < base:
                continue
            if ty in ('t','T'):
                if prev_st is None:
                    prev_st = addr
            else:
                if prev_st is not None:
                    segments.append((prev_st,addr))
                    prev_st = None
        if prev_st is not None:
            #This should be in general impossible, but what if the symbol table has a tailing 't' section?
            segments.append((prev_st,addr))
        #(file_offset,mem_addr,size)
        return map(lambda (st,ed):(st-base,st-base,ed-st),segments)
