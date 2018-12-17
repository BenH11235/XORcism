#! /usr/bin/python3
import string
import sys

def line(c,p):
    if c in string.printable and c not in string.whitespace:
        disp_c = c
    else :
        disp_c = "\\x"+"{0:0{1}x}".format(ord(c),2)
    return "(b'{}', Prob({:.6f}))".format(disp_c, round(float(p),6)) 

def display_prob_from_dict(d,name):
    for i in range(256):
        d.setdefault(chr(i),0)

    lines = []
    lines.append(f"pub const {name}:[(u8,Prob);{len(d)}] = [")
    for k in sorted(d,key=lambda x: d[x],reverse=True):
        lines.append("\t"+line(k,d[k])+",")
    lines.append("]")
    return "\n".join(lines)


b64_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + "/" + "+"
base64_dict = {c: 1/len(b64_chars) for c in b64_chars}

supported = [("BASE64", base64_dict)]


if __name__ == "__main__":
    success = False
    dist_name = sys.argv[1]
    for (const_name,const_dict) in supported:
        if dist_name == const_name:
            success = True
            print(display_prob_from_dict(const_dict,const_name))
    if success == False:
        print("Sorry, distribution not supported.")
        print("Supported distributions:")
        print("\n".join([const_name for (const_name,const_dict) in supported]))
