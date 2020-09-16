import pefile
import sys, os
import xlsxwriter
import time
import hashlib

# ScanPE.py
#
# Author: Josh Messitte
#
# Scan a directory of PE files. Intro to simple static malware analysis
#
# Usage: python ScanPE.py <filedirpath>


GOOD_EPS = [b'.text',b'.code',b'.CODE',b'INIT',b'PAGE']

# Accessor for file architecture
def getArchType(pe):
    if pe.FILE_HEADER.Machine == 0x14C:
        return '32 Bits Binary'
    elif pe.FILE_HEADER.Machine == 0x8664:
        return '64 Bits Binary'

# Accessor for Md5 Hash
def getMd5Hash(pe):
    return hashlib.md5(dat).hexdigest()


# Accessor for Imphash
def getImphash(pe):
    return pe.get_imphash()


# Accessor for sha256 hash
def getSha256Hash(pe):
    return hashlib.sha256(dat).hexdigest()

# Accessor for sha1 hash
def getSha1Hash(pe):
    return hashlib.sha1(dat).hexdigest()


# Accessor for number of file imports
def getNumImports(pe):
    return len(pe.DIRECTORY_ENTRY_IMPORT)


# Inspect entry point
def inspectEntryPoint(pe):
    name = ''
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pos = 0
    for section in pe.sections:
        if (ep >= section.VirtualAddress) and (ep < (section.VirtualAddress + section.Misc_VirtualSize)):
            name = section.Name.replace(b'\x00',b'')
            break
        else:
            pos += 1
    return ep, name, pos
# Find and store import sections
def importSections(pe):
    ret =[]
    for section in pe.sections:
        ret.append(section.Name.decode('utf-8'))
    return ret


# Find and store header members
def getHeaders(pe):
    ret =[]
    for head in pe.DOS_HEADER.dump():
        ret.append(head)
    for head in pe.NT_HEADERS.dump():
        ret.append(head)
    return ret


# Find and store optional header members
def getOHeaders(pe):
    ret = []
    for oh in pe.OPTIONAL_HEADER.dump():
        ret.append(oh)
    return ret

# Inspect timestamp
def inspectTimestamp(pe):
    val = pe.FILE_HEADER.TimeDateStamp
    ts = ''
    try:
        ts += '[%s UTC]' % time.asctime(time.gmtime(val))
        that_yr = time.gmtime(val)[0]
        this_yr = time.gmtime(time.time())[0]

        if that_yr < 2000 or that_yr > this_yr:
            ts += '[Suspicious Timestamp]'
    except:
        ts += '[Suspicious Timestamp]'

    return ts

# Main
if __name__ == '__main__':

    # Locate Directory
    dir_path = sys.argv[1]
    file_list = []
    for folder, subfolder, files in os.walk(dir_path):
        for f in files:
            complete_path = os.path.join(folder, f)
            file_list.append(complete_path)

    # Open and Excel Workbook
    sheet_name = 'Malware_Report.xlsx'
    workbook = xlsxwriter.Workbook(sheet_name)
    worksheet = workbook.add_worksheet()
    bold = workbook.add_format({'bold': True})

    # Format Columns
    row = 0
    worksheet.write('A1', 'Name', bold)
    worksheet.write('B1', 'Size', bold)
    worksheet.write('C1', 'Architecture', bold)
    worksheet.write('D1', 'Imphash', bold)
    worksheet.write('E1', 'MD5 Hash', bold)
    worksheet.write('F1', 'Sha256 Hash', bold)
    worksheet.write('G1', 'Sha1 Hash', bold)
    worksheet.write('H1', 'Date', bold)
    worksheet.write('I1', 'Entry Point Info', bold)
    worksheet.write('J1', 'Num Imports', bold)
    worksheet.write('K1', 'Import Sections', bold)
    worksheet.write('L1', 'Header Members', bold)
    worksheet.write('M1', 'Optional Headers', bold)
    row += 1

    file_num = 0

    for item in file_list:

        print("File: ", item)

        file_num += 1
        pe = pefile.PE(item)
        file = open(item, 'rb')
        dat = file.read()

        if dat == None or len(dat) == 0:
            print('Cannot read %s (It may be empty)' % file)

        # Pull architecture
        archtype = getArchType(pe)

        # Pull md5
        md5 = getMd5Hash(pe)

        # Pull imphash
        imphash = getImphash(pe)

        # Pull sha256
        sha256 = getSha256Hash(pe)

        # Pull sha1
        sha1 = getSha1Hash(pe)

        # Pull timestamp
        date = inspectTimestamp(pe)

        # Pull number of imports
        total_imports = getNumImports(pe)

        # Compile import sections
        sections = importSections(pe)
        sections_str = ''

        # Pull header members
        headers = getHeaders(pe)
        headers_str = ''

        # Pull optional headers
        opt_h = getOHeaders(pe)
        opt_h_str = ''

        # Inspect entry point
        (ep, name, pos) = inspectEntryPoint(pe)
        ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase
        ep_str = '%s %s %d/%d' % (hex(ep_ava), name, pos, len(pe.sections))

        if name not in GOOD_EPS:
            ep_str += '[Suspicious Entry Point: Not Good EP]'
        if pos == len(pe.sections):
            ep_str += '[Suspicious Entry Point: EP in last PE section]'

        # Write to xlsx file
        worksheet.write(row, 0, file.name)
        worksheet.write(row, 1, '\t\t %d bytes' % len(dat))
        worksheet.write(row, 2, archtype)
        worksheet.write(row, 3, imphash)
        worksheet.write(row, 4, md5)
        worksheet.write(row, 5, sha256)
        worksheet.write(row, 6, sha1)
        worksheet.write(row, 7, date)
        worksheet.write(row, 8, ep_str)
        worksheet.write(row, 9, total_imports)

        # Different import sections
        j = row
        for sec in sections:
            worksheet.write(j, 10, sec)
            j += 1
            sections_str += sec + ','

        # _DOS and _NT_ Headers
        x = row
        for h in headers:
            worksheet.write(x, 11, h)
            x += 1
            headers_str += h + ','


        # Optional Headers
        n = row
        for o in opt_h:
            worksheet.write(n, 12, o)
            n += 1
            opt_h_str += o + ','

        # Move row down as necessary
        row = max(j,x,n) + 1

        # Autofilter xlsx file
        worksheet.autofilter(0, 0, row, 10)
        workbook.close()

