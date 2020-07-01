#!/usr/bin/python

# We aim to extract semantic signatures of a list of patched/un-patched functions
# Input:
# sys.argv[1]: path/to/kernel dir(image, symboltable, debuginfo)
# sys.argv[2]: path/to/sigs dir(target-function-list, we also store binary signatures there
#optional: sys.argv[2]: cfgfast. change the mode of cfg generation
# Output:
# Pickle the extracted signatures in the output dir.

import angr,simuvex,claripy
import sys,os,subprocess
import logging,traceback
import copy,re
import time
import networkx
try:
    import cPickle as pickle
except ImportError:
    import pickle
from utils_sig import *
from sym_table import Sym_Table
from sym_executor import Sym_Executor

#logging.basicConfig(level=logging.DEBUG) # adjust to the wanted debug level
dbg_out = True

def locate_marks(proj,cfg,start,end):
    func_cfg = get_func_cfg(cfg,start)
    groups = {}
    for n in func_cfg.nodes():
        cblk = proj.factory.block(n.addr).capstone
        for ins in cblk.insns:
            if ins.mnemonic == 'prfm':
                #Assume the marking instruction has one of two forms:
                #(1) prfm type, [sp]
                #(2) prfm type, [sp,X]
                ops = ins.op_str.split(',')
                if len(ops) <> 2 and len(ops) <> 3:
                    print 'Unusual PRFM: ' + str(ins)
                    continue
                groups.setdefault(ops[0],[]).append((ins.address,len(ops) == 2))
    neg_marks = set()
    global find
    find.clear()
    for k in groups:
        neg_marks.clear()
        for (addr,is_pos) in groups[k]:
            if is_pos:
                pos_mark = addr
            else:
                neg_marks.add(addr)
        find[pos_mark] = neg_marks
    print 'MARKERS:'
    for p in find:
        print 'P: ' + hex(p) + ' N: ' + str([hex(x) for x in find[p]])

def states_info(tracer,states):
    if states is None:
        return
    for st in states:
        print [hex(x) for x in st.history.bbl_addrs]
        ast = tracer.get_formula(st,st.regs.x1)
        print ast

#Init the signature from a pair of pos-negs markers, which basically marks all the nodes between them as the area of interest.
#This needs us to insert some special asm instructions (e.g. PRFM) to the source code and then compile it.
def init_signature_from_markers(proj,cfg,pos,negs,options,sym_tab=None):
    default_cfg_ends = options.get('default_cfg_ends',False)
    ignore_leading_neg = options.get('ignore_leading_neg',False)
    drop_neg_node = options.get('drop_neg_node',False)
    addrs = get_node_addrs_between(cfg,pos,negs,default_cfg_ends=default_cfg_ends,ignore_leading_neg=ignore_leading_neg,has_loop=False,drop_neg_node=drop_neg_node)
    return init_signature(proj,cfg,addrs,pos=pos,negs=negs,sym_tab=sym_tab)

#We are given some instruction addrs here, we want to wrap them into a signature.
def init_signature_from_insns_aarch64(proj,cfg,addrs,options,sym_tab=None):
    node_addrs = set()
    pos = set()
    negs = set()
    o_addrs = set(addrs)
    while bool(addrs):
        addr = addrs.pop()
        n = get_node_by_addr(cfg,addr,any_addr=True)
        if not n:
            print 'No node for addr %x' % addr
            continue
        addr_in = [x for x in addrs if x >= n.addr and x < n.addr + n.size] + [addr]
        addrs -= set(addr_in) 
        addr_in = sorted(addr_in)
        node_addrs.add(n.addr)
        if addr_in[0] == n.addr:
            if addr_in[-1] == n.addr + n.size - 4:
                #The whole node belongs to the target area.
                pass
            else:
                #We have the first few instructions in the node.
                negs.add(addr_in[-1])
        else:
            if addr_in[-1] == n.addr + n.size - 4:
                #We have the last few instructions in the node.
                pos.add(addr_in[0])
            else:
                #Really strange, we hang in the middle.
                print 'Strange, we have some marked instructions hang in the middle of a node: ' + str([hex(x) for x in addr_in])
                pos.add(addr_in[0])
                negs.add(addr_in[-1])
    print '[Nodes Contained in the Sig] ' + hex_array(node_addrs)
    #print '[Pos] ' + hex_array(list(pos))
    #print '[Negs] ' + hex_array(list(negs))
    #It seems we don't need to use those options like 'default_cfg_ends', since we already have the precise marked range.
    #The pos and negs we generated are just for compatibility with legacy pos/neg interface, we can use new 'acc_list' interface now.
    return init_signature(proj,cfg,node_addrs,insns=o_addrs,sym_tab=sym_tab)

#The default_options are options controlling the behaviors of the signature extraction and matching process.
#'default_cfg_ends': if no neg markers are provided, whether to use cfg bounds as default neg markers, this can help to mark 'return' statements.
#'ignore_leading_neg': if the neg marker is just at the start of a node, whether to exclude the node. Usually we should exclude as an optimization,
#but sometimes we have 'if()then return'... In this case, the neg marker will be put before 'return' in 'if()', thus we *want* to include the 'return' node.
#'match_reg_set': when do comparison we treat all registers the same except those on this list.
#'match_ret_policy': 'free' means all functions are regarded as the same, 
#              'by_name' means we try to distinguish functions by their names in symbol table. 
#'match_conc_policy': 'free' means two concrete values (e.g. BVV) will be regarded as the same anyway.
#               'strict' means we should compare their values strictly.
#'match_ite_1_policy': if one formula is ITE and one is not, how to match them? 'no' means return False directly. 'contain' means non-ITE is one term of the ITE.
#'match_ite_2_policy': how to match two ITE formulas? 'strict' --> strictly match. 'contain' means sig's terms are contained in candidate's terms.
#'match_sym_conc_policy': how to match one symbolic value and one concrete value? 'hz' -> if the sym doesn't have 'hz_extra' formula, regard them as the same.
#                'strict' -> return False 'free' -> return True
default_options = {
    'default_cfg_ends' : True,
    'ignore_leading_neg' : True,
    'drop_neg_node' : False,
    'match_reg_set':set(),
    'match_ret_policy':'by_name',
    'match_conc_policy':'free',
    'match_ite_1_policy':'no',
    'match_ite_2_policy':'contain',
    'match_sym_conc_policy':'hz',
    'trim_tail_abs_jmp':True,
    'trim_tail_call_args':False,
    'trim_non_tail_roots':False,
    'match_fmt_str':False,
    'simplify_ast':True,
    'match_func_name_policy':'default',
    'match_load_single_mapping':False,
    'match_store_single_mapping':False,
    'match_exit_single_mapping':False,
}

def _set_extra_default_options(options):
    if 'match_reg_set' in options:
        options['match_reg_set'].add('xsp')
        options['match_reg_set'].add('sp')

#'find' is a dictionary that stores marking locations.
# mark+ --> [mark-,mark-,...]
find = {}
num_find = 10

def do_ext_sig_markers(b,start,end,options=default_options,symbol_table=None):
    #Get the CFG at first, which is the base for multiple later tasks.
    cfg = get_cfg_acc(b,start,end,cfgfast)

    #We need to locate the special 'PRFM' markings in the function CFG.
    locate_marks(b,cfg,start,end)

    sigs = []
    targets = set()
    for pos_mark in find:
        targets = targets.union(set(find[pos_mark]))
        sigs += init_signature_from_markers(b,get_func_cfg(cfg,start,proj=b,sym_tab=symbol_table),[pos_mark],find[pos_mark],options,sym_tab=symbol_table)

    exe = Sym_Executor(options=options,dbg_out=False)
    smg = exe.try_sym_exec(proj=b,cfg=cfg,cfg_bounds=[start,end],targets=targets,start=start,new_tracer=True,new_recorder=True,sigs=sigs,sym_tab=symbol_table)
    return (exe.tracer.addr_collision,sigs)

def do_ext_sig_insns(b,start,end,addrs,options=default_options,symbol_table=None):
    #Get the CFG at first, which is the base for multiple later tasks.
    cfg = get_cfg_acc(b,start,end,cfgfast)
    func_cfg = get_func_cfg(cfg,start,proj=b,sym_tab=symbol_table,simplify=True)
    
    sigs = init_signature_from_insns_aarch64(b,func_cfg,addrs,options,sym_tab=symbol_table)
    sigs = filter(is_sig_valid,sigs)
    if not sigs:
        print 'No signatures are valid, possibly they have no root instructions from initialization..'
        return (False,None)
    #Get the execution targets from the sigs.
    targets = get_cfg_bound(sigs)
    exe = Sym_Executor(options=options,dbg_out=False)
    smg = exe.try_sym_exec(proj=b,cfg=cfg,cfg_bounds=[start,end],targets=targets,start=start,new_tracer=True,new_recorder=True,sigs=sigs,sym_tab=symbol_table)
    return (exe.tracer.addr_collision,sigs)

#Due to multiple reasons (eg. Angr fails to generate the complete CFG), the initialized signature may be invalid
#(eg. contain no root instructions). Detect such cases.
def is_sig_valid(sig):
    #if 'func_existence_test' in sig.graph['options']:
    #    return True
    if sig.graph['root_ins'] and len(sig) > 0:
        return True
    return False

ARCH = 'aarch64'
BASE = 0xffffffc000080000;

#Given a CVE name, return the next available sig index for it.
sig_index = {}
def get_next_index(s):
    if s in sig_index:
        sig_index[s] += 1
        return sig_index[s]
    else:
        sig_index[s] = 0
        return 0

cfgfast=False
def ext_sig():
    global BASE
    global cfgfast
    if 'cfgfast' in sys.argv:
        cfgfast = True
    global kernelpath = sys.argv[1]
    binarypath=kernelpath+"/boot"
    symboltable_path=kernelpath+"/System.map"
    symbol_table = Sym_Table(symboltable_path)
    BASE = symbol_table.probe_arm64_kernel_base()
    code_segments = symbol_table.get_code_segments(BASE)
    b = load_kernel_image(binarypath,ARCH,BASE,segments=code_segments)
    #Format of the function list file (argv[2]/ext_list):
    #[cve] [func_name] [line numbers] [key:val] [key:val] ...
    perf_vec = []
    extlistpath = sys.argv[2]+'/ext_list'
    sigspath = sys.argv[2]+'/sigs'
    os.mkdir(sigspath)
    with open(extlistpath,'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line[0] == '#':
                continue
            tokens = line.split(' ')
            cve = tokens[0].split("_")[0]
            func_name = tokens[1]
            lnos = _parse_line_nos(tokens[2])
            if tokens[-1].startswith('hosthostfunc'):
                hosthostfunc=tokens[-1].split(":")[1]
                hostfunc=hosthostfunc.split("--")[-1]
            else:
                hosthostfunc=None
                hostfunc=func_name

            t0 = time.time()
            (addrs,entry) = get_addrs_from_lines_aarch64(kernelpath,func_name,lnos,hosthostfunc)
            if len(addrs)==0:
                print "no addrs!! kernel:",kernel,"func_name:",func_name,"lnos: ",lnos,"hosthostfunbc: ",hosthostfunc
                continue
            aset = set()
            print '[Instructions Involved]'
            for ln in sorted(list(addrs)):
                aset = aset.union(addrs[ln])
                print '%d: %s' % (ln,str([hex(x) for x in sorted(list(addrs[ln]))]))
            
            (ty,func_addr,func_size) = entry
            options = copy.deepcopy(default_options)
            _parse_options(options,tokens[3:])
            _set_extra_default_options(options)
            if 'func_existence_test' in options:
                print '-----------Pure Function Existence Testing------------'
                print '%s func_name: %s, target_func: %s' % (cve,func_name,options['func_existence_test'])
                sig = networkx.DiGraph()
                sig_name = cve+'-sig-%d' % get_next_index(cve)
                sig.graph['sig_name'] = sig_name
                sig.graph['func_name'] = func_name
                sig.graph['options'] = options
                if hosthostfunc:
                    sig.graph['hosthostfunc']=hosthostfunc
                with open(sigspath+'/'+sig_name,'wb') as fs:
                    pickle.dump(sig,fs,-1)
                perf_vec += [(sig_name,time.time()-t0)]
                continue
            retry_cnt = 1
            while retry_cnt > 0:
                (collision,sigs) = do_ext_sig_insns(b,func_addr,func_addr+func_size,aset,options,symbol_table)
                if not collision:
                    break
                else:
                    print 'Addr collision occurred when trying to extract sig %s in function %s, retry... %d' % (cve,func_name,retry_cnt)
                retry_cnt = retry_cnt - 1
            if not sigs:
                print '!!! No signature generated..'
                continue
            #print sigs
            sig_ind = get_next_index(cve)
            perf_vec += [(cve+'-sig-%d' % sig_ind,time.time()-t0)]
            for i in range(len(sigs)):
                #Record some global information in sig.
                sigs[i].graph['func_name'] = func_name
                if hosthostfunc:
                    sigs[i].graph['hosthostfunc']=hosthostfunc
                if len(sigs) > 1:
                    sig_name = cve+'-sig-%d-%d' % (sig_ind,i)
                else:
                    sig_name = cve+'-sig-%d' % sig_ind
                sigs[i].graph['sig_name'] = sig_name
                sigs[i].graph['options'] = options
                simplify_signature(sigs[i])
                analyze_func_args_aarch64(binarypath,BASE,sigs[i],options)
                trim_signature(sigs[i],addrs,options)
                show_signature(sigs[i])
                print "sig_name: ",sig_name
                with open(sigspath+'/'+sig_name,'wb') as fs:
                    pickle.dump(sigs[i],fs,-1)

ADDR2LINE = '/home/zheng/fiberaarch64-linux-android-4.9/bin/aarch64-linux-android-addr2line'
def get_lineinfo(l):
    if l.startswith('0x'):
        inline=False
        tokens = l.split(':')
        addr = int(tokens[0],16)
        func = tokens[1].split(' ')[1]
        lno = int(tokens[2].split(' ')[0])
    elif l.startswith(' (inlined'):
        inline=True
        tokens = l.split(':')
        lno = int(tokens[1].split(' ')[0])
        func = tokens[0].split(' ')[3]
        addr=None
    else:
        print 'Unrecognized ADDR2LINE output!!!'
        return (None,None,None,None)
    return (inline,addr,func,lno)

#Use addr2line to find the instructions addrs related to the lines numbers in source code.
def get_addrs_from_lines_aarch64(kernelpath,fname,lines,hosthostfunc=None):
    hostfunc=fname
    hosthostfunclist=None
    if hosthostfunc:
        hosthostfunclist=hosthostfunc.split('--')
        hosthostfunc=hosthostfunclist[-1]
        hostfunc=hosthostfunc
    sym_tablepath=kernelpath+"/System.map"
    symbol_table=Sym_Table(sym_tablepath)
    entrylist = symbol_table.lookup_func_name(hostfunc,2)
    if entrylist is None:
        print 'Cannot locate function ' + hostfunc +" in symble table "+sym_tablepath
        entry=symbol_table.lookup_func_name(hostfunc,1)
        if entry is None:
            return (set([]),None)
        else:
            entrylist=[entry]
    for entry in entrylist:
        f_buf=get_func_debuginfo(kernelpath,entry)
        addrs=get_addrs_from_lines_aarch64_2(fname,lines,hosthostfunc,f_buf,hosthostfunclist)
        if len(addrs) > 0:
            print 'get suitable entry:'
            print (entry[0],hex(entry[1]),hex(entry[2]))
            break
    #sometimes the funcname in symbol table is a little different
    if len(addrs)==0:
        print 'addrs ==0 try mode11'
        entry=symbol_table.lookup_func_name(hostfunc,1)
        f_buf=get_func_debuginfo(kernelpath,entry)
        addrs=get_addrs_from_lines_aarch64_2(fname,lines,hosthostfunc,f_buf,hosthostfunclist)
    return (addrs,entry)

def get_addrs_from_lines_aarch64_2(fname,lines,hosthostfunc,f_buf,hosthostfunclist=None):
    addrs = {}
    if hosthostfunc:
        for i in range(len(f_buf)):
            line=trim(f_buf[i])
            (inline,addr2,func,lno)=get_lineinfo(line)
            if addr2:
                addr=addr2
            if func == fname and lno in lines:
                j=1
                for hostfunc in hosthostfunclist:
                    newline=trim(f_buf[i+j])
                    (newinline,newaddr,newfunc,newlno)=get_lineinfo(newline)
                    if newfunc != hostfunc:
                        break
                    j +=1
                #matched
                else:
                    addrs.setdefault(lno,set()).add(addr)
        return addrs
    #not hosthostfunc
    for l in f_buf:
        l = trim(l)
        (inline,addr2,func,lno)=get_lineinfo(l)
        if addr2:
            addr=addr2
            #E.g.
            #0xffffffc000a7aa9c: wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:59
            #0xffffffc000a7ab18: wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:77 (discriminator 1)
            # (inlined by) wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:66
        if func == fname and lno in lines:
            addrs.setdefault(lno,set()).add(addr)
    return addrs

def _parse_line_nos(s):
    #Format of line numbers: 1,2-10,11 No spaces.
    lines = set()
    tokens = s.split(',')
    for t in tokens:
        if '-' in t:
            nums = t.split('-')
            lines.update(set(range(int(nums[0]),int(nums[1])+1)))
        else:
            lines.add(int(t))
    return lines
    

def _parse_options(options,tlist):
    for opt in tlist:
        kv = opt.split(':')
        if len(kv) <> 2:
            continue
        if kv[1] == 'True':
            kv[1] = True
        elif kv[1] == 'False':
            kv[1] = False
        elif kv[1].find(',') >= 0:
            kv[1] = set(kv[1].split(','))
        options[kv[0]] = kv[1]

if __name__ == '__main__':
    ext_sig()
