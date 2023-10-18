 #!/usr/bin/python

import os
import glob
import pytsk3
import wmi
import re
import argparse
from pathlib import Path
import shutil
from tqdm import tqdm
import time
import logging
import traceback

l = logging.getLogger()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ColorCodes:
    grey = "\x1b[38;21m"
    green = "\x1b[1;32m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    blue = "\x1b[1;34m"
    light_blue = "\x1b[1;36m"
    purple = "\x1b[1;35m"
    reset = "\x1b[0m"

class CustomFormatter(logging.Formatter):
    format_info = "[#]  %(message)s"
    format_error = "[!]  %(message)s"
    format_debug = "[-]  %(message)s"
    format_critical = "[*]  %(message)s"

    FORMATS = {
        logging.DEBUG: ColorCodes.blue + format_debug + ColorCodes.reset,
        logging.INFO: ColorCodes.green + format_info + ColorCodes.reset,
        logging.WARNING: ColorCodes.yellow + format_info + ColorCodes.reset,
        logging.ERROR: ColorCodes.red + format_error + ColorCodes.reset,
        logging.CRITICAL: ColorCodes.bold_red + format_critical + ColorCodes.reset,
        'ignore_color': format_info
    }

    def __init__(self, ignore_color=False):
        self.ignore_color = ignore_color

    def format(self, record):
        if self.ignore_color:
            log_fmt = self.FORMATS.get('ignore_color')
        else:
            log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def logger_setup(verbose):
    # Log configuration
    if(verbose):
        l.setLevel(logging.DEBUG)
        #log handlers
        screen = logging.StreamHandler()
        screen.setLevel(logging.DEBUG)
        screen.setFormatter(CustomFormatter())
        #debug_log = logging.FileHandler('debug.log')
        #debug_log.setLevel(logging.DEBUG)
        #debug_log.setFormatter(CustomFormatter(ignore_color=True))
        l.addHandler(screen)
        #l.addHandler(debug_log)

        '''l.basicConfig(
            level=l.DEBUG,
            format="%(asctime)s [%(levelname)s]   \t%(message)s",
            handlers=[
                l.FileHandler("debug.log"),
                l.StreamHandler()
            ]
        )'''
    else:
        l.setLevel(logging.INFO)
        #log handlers
        screen = logging.StreamHandler()
        screen.setLevel(logging.INFO)
        screen.setFormatter(CustomFormatter())
        #debug_log = logging.FileHandler('debug.log')
        #debug_log.setLevel(logging.INFO)
        #debug_log.setFormatter(CustomFormatter(ignore_color=True))
        l.addHandler(screen)
        #l.addHandler(debug_log)

        '''l.basicConfig(
            level=l.INFO,
            format="%(asctime)s [%(levelname)s]   \t%(message)s",
            handlers=[
                l.FileHandler("debug.log"),
                l.StreamHandler()
            ]
        )'''

def convert_mount_to_disk(drive_letter):
    """
    This will take a drive mount point and convert it to the physical disk that owns
    the drive.
        Dependencies:
            wmi - credit to Tim Golden - https://pypi.org/project/WMI/
    """
    try:
        w = wmi.WMI()
        for drive in w.win32_LogicalDiskToPartition():
            physical_disk_id = drive.Antecedent.deviceid
            logical_disk_id = drive.Dependent.DeviceID
            l.debug(f'PHYSICAL DISK ID: {physical_disk_id} | LOGICAL DISK ID: {logical_disk_id}')
            if logical_disk_id == drive_letter:
                l.debug(f'Identified the drive mapping')
                s = re.compile('(Disk #)(\d)')
                m = s.match(physical_disk_id)
                physical_disk_number = m.group(2)
                break

        physical_disk_string = "\\\\.\\PhysicalDrive" + str(physical_disk_number)
        l.info(f'Physical Disk mapping: {physical_disk_string}')

    except Exception as e:
        l.error(f'Failed to find the mapping for of the physical drive..\n{e}\n{traceback.format_exc()}')

    return physical_disk_string


def get_data_partition(physical_disk):
    """
    Iterates the partitions on the physical disk.
    Finds and returns the basic data partition on the disk.
    This can be broken if the physical disk has more than one basic data partition.
    TODO:
        Find all of the basic data partitions and put them into an array for reference later.
    :param physical_disk:
    :return: partition_handle
    """
    try:
        disk_handle = pytsk3.Img_Info(physical_disk)
        partition_table = pytsk3.Volume_Info(disk_handle)
        partition_handle = None
        largest = 0
        partition_id = None

        # sorting the partitions looking for the data
        for partition in partition_table:
            if partition.len > largest:
                largest = partition.len
                partition_id = partition.addr
            else:
                continue

        # getting a handle
        for partition in partition_table:
            if partition.addr == partition_id:
                partition_handle = pytsk3.FS_Info(disk_handle, offset=(partition.start * 512))
                l.info(f"Found data partition")

        return partition_handle
    
    except Exception as e:
        l.error(f'Error: {e}\n{traceback.format_exc()}')


def extract_usnj_attributes(partition_handle, destination_dir, keep_dirstruct):
    """
    Finds the usnjrnl:$j attribute and extracts it to a file at the destination_dir.
    :param partition_handle:
    :param destination_dir:
    :return: None
    """
    try:
        usnj = partition_handle.open(r'$Extend/$UsnJrnl')

        if keep_dirstruct:
            destination_dir = Path(str(destination_dir) + '\\' + '$Extend\$UsnJrnl')
            os.makedirs(destination_dir)

        if not destination_dir.exists:
                os.makedirs(destination_dir)

        for attribute in usnj:
            if attribute.info.name == b'$J':
                l.info(f"Carving USN attribute: {attribute.info.name.decode()}")
                extract_file_attributes(usnj, attribute, destination_dir)
                l.info(f"Finished carving: {attribute.info.name.decode()}")

            if attribute.info.name == b'$Max':
                l.info(f"Carving USN attribute: {attribute.info.name.decode()}")
                extract_file_attributes(usnj, attribute, destination_dir)
                l.info(f"Finished carving: {attribute.info.name.decode()}")

    except Exception as e:
        l.error(f'Error: {e}\n{traceback.format_exc()}')

def extract_file_attributes(file, attribute, destination_dir):
    """
    Extracts a file's attributes.
    :param file:
    :param attribute:
    :param destination_dir:
    :return:
    """
    try:
        if not destination_dir.exists:
                os.makedirs(destination_dir)

        out_file = open(str(destination_dir) + '\\' + attribute.info.name.decode(), 'w')
        out_file.write("")
        out_file.close()

        out_file = open(str(destination_dir) + '\\' + attribute.info.name.decode(), 'ab')
        MAX = 10240000 # Number came back with highest efficiency based on testing. Not the largest chunk possible
        size = attribute.info.size
        sparse = True

        # need to buffer and read in a loop for large files
        if size > MAX:
            i = 0
            offset = 0
            remainder = size % MAX
            iterations = size//MAX

            for i in tqdm(range(iterations+1)):
                if i == iterations:
                    #if not sparse:
                    out_file.write(file.read_random(offset, remainder, attribute.info.type, attribute.info.id))

                else:
                    # check if sparse file, trim the fat
                    usn_data = file.read_random(offset, remainder, attribute.info.type, attribute.info.id)
                    if sparse:
                        for b in usn_data: 
                            if b != 0:
                                sparse = False
                                break

                    if not sparse:
                        out_file.write(usn_data)

                    offset += MAX


        else:
            out_file.write(file.read_random(0, size, attribute.info.type, attribute.info.id))

        out_file.close()

    except Exception as e:
        l.error(f'Error: {e}\n{traceback.format_exc()}')


def extract_file(file_name, partition_handle, destination_dir, keep_dirstruct):
    """
    Extracts a file.
    :param file_name:
    :param partition_handle:
    :param destination_dir:
    :return: None
    """
    try:
        
        if not destination_dir.exists():
            os.mkdir(destination_dir)

        if keep_dirstruct:
            destination_dir = Path(str(destination_dir) + '\\' + str(Path(file_name).parent))
            if not destination_dir.exists:
                os.makedirs(destination_dir)
        
        file_handle = partition_handle.open(file_name)

        f = Path(str(destination_dir) + '\\' + file_handle.info.name.name.decode())
        l.debug(f"Carving: {f}")
        out_file = open(f, 'wb')
        
        if (file_name == r'$MFT') or (file_name == r'$LogFile'):
            l.info(f"Carving: {f}")

        out_file.write(file_handle.read_random(0, file_handle.info.meta.size))
        out_file.close()
    
    except Exception as e:
        l.error(f'Error carving {file_name}: {e}\n{traceback.format_exc()}')


def copy_files(source_files, keep_dirstruct, out_dir):
    failed_to_extract = []
    failed_to_extract_files = []

    l.info("Started triage")

    if not out_dir.exists():
        os.mkdir(out_dir)

    for file in tqdm(source_files):
        try:
            if keep_dirstruct:
                destination_directory = str(out_dir.parent) + "\\" + str(os.path.split(Path(file))[0]).replace(":", "")
                l.debug(f"Extracting: {file}")
                shutil.copy2(file, destination_directory)   

            else: 
                destination_directory = str(out_dir) + "\\" + str(os.path.split(Path(file))[1])
                l.debug(f"Extracting: {file}")
                shutil.copy2(file, destination_directory)

        except Exception as e:
            l.debug(f"Failed to extract: {file}")
            failed_to_extract_files.append(file)
            failed_to_extract.append(str(file))
            continue

    if failed_to_extract:
        l.critical(f"Failed to extract some files. Carving will begin shortly.{bcolors.ENDC}")

    l.info(f"Finished triage")

    return failed_to_extract_files

def deduplicate_list(dup_list):
    """

    """
    deduplicated = list()

    for i in dup_list:
        if i not in deduplicated:
            deduplicated.append(i)

    return deduplicated

def list_files(file_list_file, drive_letter, extract_path_base, keep_dirstruct):
    """

    """
    f = open(file_list_file, 'r')
    full_list = []
    for line in f:
        line = drive_letter + line.replace("\n", "")
        full_list += glob.glob(line, recursive=True)

    file_list = []
    dir_list = []
    destination_dir = []
    destination_files = []

    extract_path_base = Path(extract_path_base)

    if not extract_path_base.exists():
        os.mkdir(extract_path_base)

    for i in full_list:
        i = Path(i)
        if i.is_file():
            file_list.append(i)
            destination_files.append(str(extract_path_base) + os.path.splitdrive(i)[1])

            dir_list.append(os.path.split(i)[0])
            destination_dir.append(os.path.split(Path(str(extract_path_base) + os.path.splitdrive(i)[1]))[0])

    destination_dir = deduplicate_list(destination_dir)

    if keep_dirstruct:
        for d in destination_dir:
            if not Path(d).exists():
                os.makedirs(d)

    f.close()

    return destination_files, file_list

def main():
    parser = argparse.ArgumentParser(
        description='carve.py is a tool to help collect files from a mounted file system. You can collect $UsnJrnl:$J, $MFT, other locked system files as as well as regular files. Be aware that not all attributes are copied. Timestamps are retained on files that are not locked. BUt ACLs and other information may be lost.')
    parser.add_argument('-d','--drive', dest='drive_letter', action='store', type=str, default=None, required=True,
                        help='Logical drive to extract from (e.g., "F:")')
    parser.add_argument('-o','--out', dest='out_dir', action='store', type=str, default=None, required=True,
                        help='Destination directory to extract files to.')
    parser.add_argument('--mft', action=argparse.BooleanOptionalAction,
                        help='Optional. Extracts $MFT.')
    parser.add_argument('--usnj', action=argparse.BooleanOptionalAction,
                        help='Optional. Extracts NTFS $UsnJrnl:$J, $UsnJrnl:$MAX and $LogFile.')
    parser.add_argument('-t', '--triage', action=argparse.BooleanOptionalAction,
                        help='Optional. Extracts a triage of files based on the --triage-filter option.')
    parser.add_argument('-f','--triage-filter', dest='file_list', action='store', type=str, default=None,
                        help='Required if --triage is used. Provides the path to a list of files to extract. If extraction fails, then it carves the file byte for byte into a new file')
    parser.add_argument('-k','--keep-dirstruct', action=argparse.BooleanOptionalAction,
                        help='Optional. Keeps the source directory stucture.')
    parser.add_argument('-v','--verbose', action=argparse.BooleanOptionalAction,
                        help='Default is False. Enable for debugg logging.')
    args = parser.parse_args()

    
    logger_setup(args.verbose)

    start = time.perf_counter()
    print(f'{bcolors.WARNING}\
########################################################\n\
 _________     _____   __________ ___   _______________ \n\
 \_   ___ \   /  _  \  \______   \\\\  \ /   /\_   _____/ \n\
 /    \  \/  /  /_\  \  |       _/ \  \   /  |    __)_  \n\
 \     \____/    |    \ |    |   \  \    /   |        \ \n\
  \______  /\____|__  / |____|_  /   \__/   /_______  / \n\
         \/         \/         \/           @HurDFIR\/ \n\
########################################################{bcolors.ENDC}')
    l.debug(f'Arguments: {args}')
    physical_disk = convert_mount_to_disk(args.drive_letter)
    partition_handle = get_data_partition(physical_disk)

    mount_letter = args.drive_letter.replace(":", "")
    
    cwd = os.getcwd()
    extract_path_base = Path(args.out_dir)

    if not extract_path_base.exists():
        os.makedirs(extract_path_base)

    failed_files_path = str(extract_path_base) + '\\' + '__failed_files.txt'
    f = open(failed_files_path, 'w')
    f.write("These files failed the normal extraction process.\nHowever, they may have been carved byte for byte into a new file. If this is the case, then the file's metadata cannot be trusted.\n\n")
    f.close

    if(args.keep_dirstruct):
        extract_path_base = Path(str(extract_path_base) + "\\" + mount_letter)
        
        if not extract_path_base.exists():
            os.makedirs(extract_path_base)

    if args.mft: 
        extract_file(r'$MFT', partition_handle, extract_path_base, args.keep_dirstruct),

    if args.usnj:
        extract_usnj_attributes(partition_handle, extract_path_base, args.keep_dirstruct)
        extract_file(r'$LogFile', partition_handle, extract_path_base, args.keep_dirstruct)

    if args.triage and args.file_list:
        destination_files, source_files = list_files(file_list_file=args.file_list, drive_letter=args.drive_letter, extract_path_base=extract_path_base, keep_dirstruct=args.keep_dirstruct)
        failed_files = copy_files(source_files, args.keep_dirstruct, extract_path_base)
        if failed_files:
            f = open(failed_files_path, 'a')
            l.critical(f"Trying to carve the failed files")
            for file in failed_files:
                try:
                    f.write(str(file) + "\n")
                    relative_file_path = (str(file).replace(args.drive_letter + "\\", "")).replace("\\", "/")
                    extract_file(relative_file_path, partition_handle, extract_path_base, args.keep_dirstruct)

                except Exception as e:
                    l.error(f"Error: {e}\n{traceback.format_exc()}")
                    continue

            l.critical(f"Finished carving the failed files")

    if not (args.mft or args.usnj or args.triage):
        l.error("You must specify one of --usnj, --mft, --triage. Exiting...")

    stop = time.perf_counter()
    l.warning(f"Script took {stop - start:0.4f} seconds")

if __name__ == "__main__":
    main()
