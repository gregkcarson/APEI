import sys
import socket
import random
import getopt
from optparse import OptionParser
import os
import signal
from time import sleep, ctime
import pefile

def main():
    
    print
    print "***************************************************************************"
    print "*  APEI - Amateur Portable Executable Inspection - v1 gregkcarson@gmail.com *"
    print "---------------------------------------------------------------------------"    
    print "  'I thought what I'd do was, I'd pretend I was one of those deaf-mutes.'  "
    print "---------------------------------------------------------------------------"
    print " This is a really basic PE file parser that attempts to print a basic      "  
    print " summary of information regarding a particular PE file provided by a user. "
    print " It will also attempt to identify a possible codecave."
    print

    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage, version="Welcome to %prog, gregkcarson@gmail.com for questions v1.0")
    parser.add_option("-v","--verbose",action="store_true",dest="verbose", help="LOUD NOISES")
    parser.add_option("-q","--quiet", action="store_false",dest="verbose", help="shhhhhhh")
    parser.add_option("-f","--file",type="string",dest="file",help="Specify the full path and name of the PE file you want to analyze.")
    parser.add_option("-s","--searchf",type="string",dest="searchf",help="Specify a function name and APET will identify if it is loaded.")
    options,args=parser.parse_args()    
    
    if options.file is not None:
        global victim
        file = options.file
    else:
        print "Review usage. See help."    
        
    if options.searchf is not None:
        global search
        searchf = options.searchf
    else:
        print "Review usage. See help."    

    print "[*] Attempting to open file: "+file
    
    try:
        pe=pefile.PE(file)
    except Exception,e:
        print "[-] Error while opening requested file:"
        print e
        
    if pe.is_dll()==True or pe.is_driver()==True:
        print "[-] You have not provided a valid PE file. Quitting."
        sys.exit(0)
        
    print "[+] File successfully opened."
    print
    
    print "[*] Printing summary of PE file information."
    print
    
    print "[*] DOS_HEADER DETAILS"
    print "[+] Magic Number:"+hex(pe.DOS_HEADER.e_magic)
    print "[+] Pages in File:"+hex(pe.DOS_HEADER.e_cp)
    print "[+] Offset to NT Data:"+hex(pe.DOS_HEADER.e_lfanew)
    print
    
    print "[*] FILE_HEADER Details"
    print "[+] Machine:"+hex(pe.FILE_HEADER.Machine)    
    print "[+] Number of Sections:"+hex(pe.FILE_HEADER.NumberOfSections)    
    print "[+] Size of Optional Header:"+hex(pe.FILE_HEADER.SizeOfOptionalHeader)    
    print
    
    print "[*] OPTIONAL_HEADER Details"
    print "[+] Address of Entrypoint:"+hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)    
    print "[+] Image Base:"+hex(pe.OPTIONAL_HEADER.ImageBase)  
    print
    
    print "[*] Section Information"
    for section in pe.sections:
        print (section.Name, hex(section.VirtualAddress),
               hex(section.Misc_VirtualSize), section.SizeOfRawData )  
        
    print
    print "[*] Loaded DLLs"
    for dlls in pe.DIRECTORY_ENTRY_IMPORT:
        print "[+]"+dlls.dll
        
    print    
    print "[*] Searching for Code Cave"
    for section in pe.sections:
        if section.Characteristics & 0x20000020 == 0x0:
            continue
        if section.SizeOfRawData <= section.Misc_VirtualSize:          
            continue
        codecave = section.SizeOfRawData - section.Misc_VirtualSize
        print "[+] Identified in section "+section.Name+". Cave Size: "+str(codecave)+" bytes."
        print "[+] Section Name:"
        print section.Name
        print "[+] Section Virtual Address:"
        print section.VirtualAddress     
        print "[+] RVA:"
        rva = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        print rva
        phystovirt=section.VirtualAddress-section.PointerToRawData
        realoffset=rva-phystovirt
        print "[+] Physical Offset"
        print realoffset
    print
    print "[*] Searching For Requested Function: "+searchf
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for func in entry.imports:
            if str(func.name) in searchf:
                print '\t[+] Found in library',entry.dll
                print '\t[+] Found at: ',hex(func.address)
               
if __name__=='__main__':
    main()
