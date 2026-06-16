import json, re, sys

# opcode name -> byte (Bitcoin script). Names as they appear in Core test vectors.
OPS = {}
def add(name,val): OPS[name]=val; OPS['OP_'+name]=val
# push/const
add('0',0); add('FALSE',0); add('PUSHDATA1',76); add('PUSHDATA2',77); add('PUSHDATA4',78)
add('1NEGATE',79); add('RESERVED',80); add('TRUE',81)
for i in range(1,17): add(str(i),80+i); 
add('1',81)  # ensure
for i in range(1,17): OPS['OP_%d'%i]=80+i
# flow
for n,v in [('NOP',97),('VER',98),('IF',99),('NOTIF',100),('VERIF',101),('VERNOTIF',102),
('ELSE',103),('ENDIF',104),('VERIFY',105),('RETURN',106),
('TOALTSTACK',107),('FROMALTSTACK',108),('2DROP',109),('2DUP',110),('3DUP',111),
('2OVER',112),('2ROT',113),('2SWAP',114),('IFDUP',115),('DEPTH',116),('DROP',117),
('DUP',118),('NIP',119),('OVER',120),('PICK',121),('ROLL',122),('ROT',123),('SWAP',124),
('TUCK',125),('CAT',126),('SUBSTR',127),('LEFT',128),('RIGHT',129),('SIZE',130),
('INVERT',131),('AND',132),('OR',133),('XOR',134),('EQUAL',135),('EQUALVERIFY',136),
('RESERVED1',137),('RESERVED2',138),('1ADD',139),('1SUB',140),('2MUL',141),('2DIV',142),
('NEGATE',143),('ABS',144),('NOT',145),('0NOTEQUAL',146),('ADD',147),('SUB',148),
('MUL',149),('DIV',150),('MOD',151),('LSHIFT',152),('RSHIFT',153),('BOOLAND',154),
('BOOLOR',155),('NUMEQUAL',156),('NUMEQUALVERIFY',157),('NUMNOTEQUAL',158),('LESSTHAN',159),
('GREATERTHAN',160),('LESSTHANOREQUAL',161),('GREATERTHANOREQUAL',162),('MIN',163),('MAX',164),
('WITHIN',165),('RIPEMD160',166),('SHA1',167),('SHA256',168),('HASH160',169),('HASH256',170),
('CODESEPARATOR',171),('CHECKSIG',172),('CHECKSIGVERIFY',173),('CHECKMULTISIG',174),
('CHECKMULTISIGVERIFY',175),('NOP1',176),('CHECKLOCKTIMEVERIFY',177),('NOP2',177),
('CHECKSEQUENCEVERIFY',178),('NOP3',178),('NOP4',179),('NOP5',180),('NOP6',181),('NOP7',182),
('NOP8',183),('NOP9',184),('NOP10',185),('CHECKSIGADD',186)]:
    add(n,v)

def push(data):
    n=len(data)
    if n<76: return bytes([n])+data
    if n<256: return bytes([76,n])+data
    if n<65536: return bytes([77,n&0xff,(n>>8)&0xff])+data
    return bytes([78])+n.to_bytes(4,'little')+data

def scriptnum(n):
    if n==0: return b''
    neg=n<0; a=abs(n); out=bytearray()
    while a: out.append(a&0xff); a>>=8
    if out[-1]&0x80: out.append(0x80 if neg else 0)
    elif neg: out[-1]|=0x80
    return bytes(out)

def parse(s):
    out=bytearray()
    for w in s.split():
        if w=='' : continue
        if re.fullmatch(r'-?\d+', w):
            n=int(w)
            if n==-1: out.append(79)
            elif n==0: out.append(0)
            elif 1<=n<=16: out.append(80+n)
            else: out+=push(scriptnum(n))
        elif w.startswith('0x'):
            out+=bytes.fromhex(w[2:])
        elif w.startswith("'") and w.endswith("'"):
            out+=push(w[1:-1].encode())
        elif w in OPS:
            out.append(OPS[w])
        else:
            raise ValueError('unknown token %r'%w)
    return bytes(out)

import sys
inp=sys.argv[1] if len(sys.argv)>1 else 'script_tests.json'
outp=sys.argv[2] if len(sys.argv)>2 else 'script_tests_hex.json'
rows=json.load(open(inp))
out=[]
skipped=0
for row in rows:
    if len(row)==1: continue   # comment
    wit=None; amount=0; i=0
    if isinstance(row[0], list):
        wit=row[0][:-1]; amount=int(round(float(row[0][-1])*1e8)); i=1
    try:
        sig=parse(row[i]); pk=parse(row[i+1]); flags=row[i+2]; expected=row[i+3]
    except Exception as e:
        skipped+=1; continue
    out.append([sig.hex(), pk.hex(), flags, expected,
                [bytes.fromhex(x).hex() for x in (wit or [])], amount])
json.dump(out, open(outp,'w'))
print('compiled',len(out),'cases, skipped',skipped)
