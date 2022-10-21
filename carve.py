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


def convert_mount_to_disk(drive_letter):
    """
    This will take a drive mount point and convert it to the physical disk that owns
    the drive.
        Dependencies:
            wmi - credit to Tim Golden - https://pypi.org/project/WMI/
    """
    w = wmi.WMI()
    for drive in w.win32_LogicalDiskToPartition():
        physical_disk_id = drive.Antecedent.deviceid
        logical_disk_id = drive.Dependent.DeviceID

        if logical_disk_id == drive_letter:
            s = re.compile('(Disk #)(\d)')
            m = s.match(physical_disk_id)
            physical_disk_number = m.group(2)

    physical_disk_string = "\\\\.\\PhysicalDrive" + str(physical_disk_number)

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
    disk_handle = pytsk3.Img_Info(physical_disk)
    #print(f"PHYSICAL DISK IS {physical_disk}")
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
            print(f"{bcolors.OKGREEN}[*] Success: found data partition{bcolors.ENDC}")

    return partition_handle


def extract_usnj_attributes(partition_handle, destination_dir):
    """
    Finds the usnjrnl:$j attribute and extracts it to a file at the destination_dir.
    :param partition_handle:
    :param destination_dir:
    :return: None
    """
    usnj = partition_handle.open(r'$Extend/$UsnJrnl')

    for attribute in usnj:
        if attribute.info.name == b'$J':
            print("[-] Carving USN attribute: %s" % (attribute.info.name.decode()))
            extract_file_attributes(usnj, attribute, destination_dir)
            print(f"{bcolors.OKGREEN}[*] Finished extracting: %s{bcolors.ENDC}" % (attribute.info.name.decode()))

        if attribute.info.name == b'$Max':
            print("[-] Extracting: %s" % (attribute.info.name.decode()))
            extract_file_attributes(usnj, attribute, destination_dir)
            print(f"{bcolors.OKGREEN}[*] Finished carving USN attribute: %s{bcolors.ENDC}" % (attribute.info.name.decode()))


def extract_file_attributes(file, attribute, destination_dir):
    """
    Extracts a file's attributes.
    :param file:
    :param attribute:
    :param destination_dir:
    :return:
    """
    out_file = open(destination_dir + attribute.info.name.decode(), 'w')
    out_file.write("")
    out_file.close()

    out_file = open(destination_dir + attribute.info.name.decode(), 'ab')
    MAX = 10240000 # Number came back with highest efficiency based on testing. Not the largest chunk possible
    size = attribute.info.size

    # need to buffer and read in a loop for large files
    if size > MAX:
        i = 0
        offset = 0
        remainder = size % MAX
        iterations = size//MAX

        for i in tqdm(range(iterations+1)):
            if i == iterations:
                out_file.write(file.read_random(offset, remainder, attribute.info.type, attribute.info.id))

            else:
                out_file.write(file.read_random(offset, MAX, attribute.info.type, attribute.info.id))
                offset += MAX


    else:
        out_file.write(file.read_random(0, size, attribute.info.type, attribute.info.id))

    out_file.close()


def extract_file(file_name, partition_handle, destination_dir):
    """
    Extracts a file.
    :param file_name:
    :param partition_handle:
    :param destination_dir:
    :return: None
    """
    file_handle = partition_handle.open(file_name)
    out_file = open(destination_dir + file_handle.info.name.name.decode(), 'wb')

    if (file_name == r'$MFT') or (file_name == r'$LogFile'):
        print(f"{bcolors.OKGREEN}[*] Carving: %s{bcolors.ENDC}" % file_name)

    out_file.write(file_handle.read_random(0, file_handle.info.meta.size))
    #print(f"{bcolors.OKGREEN}[*] Finished extracting: %s{bcolors.ENDC}" % file_name)
    out_file.close()


def copy_files(source_files):
    failed_to_extract = []
    failed_to_extract_files = []

    print("[-] Started triage")
    for file in tqdm(source_files):
        try:
            destination_directory = str(os.path.split(Path(file))[0]).replace(":", "")
            #print("[-] Extracting: %s" % file)
            shutil.copy2(file, destination_directory)
            #print(f"{bcolors.OKGREEN}[*] Finished extracting: %s{bcolors.ENDC}" % file)

        except Exception as e:
            failed_to_extract_files.append(file)
            failed_to_extract.append(str(file))
            continue

    if failed_to_extract:
        print(f"{bcolors.WARNING}[!] Failed to extract some files. Carving will begin shortly.{bcolors.ENDC}")

    print(f"{bcolors.OKGREEN}[*] Finished triage{bcolors.ENDC}")

    return failed_to_extract_files


def trailing_slash(string):
    """
    Takes a sting and adds a trailing slash, if it does not have it.
    :param string:
    :return: an edited string with a trailing slash
    """
    if not string.endswith('\\'):
        string += '\\'

    return string


def create_extraction_dir():
    exit()


def deduplicate_list(dup_list):
    """

    """
    deduplicated = list()

    for i in dup_list:
        if i not in deduplicated:
            deduplicated.append(i)

    return deduplicated


def list_files(file_list_file, drive_letter):
    """

    """
    f = open(file_list_file, 'r')
    full_list = []
    for line in f:
        line = drive_letter + line.replace("\n", "")
        # print(line)
        full_list += glob.glob(line, recursive=True)

    file_list = []
    dir_list = []
    destination_dir = []
    destination_files = []

    mount_letter = drive_letter.replace(":", "")
    cwd = os.getcwd()
    extract_path_base = Path(cwd + "\\" + mount_letter)

    if not extract_path_base.exists():
        os.mkdir(extract_path_base)

    for i in full_list:
        i = Path(i)
        if i.is_file():
            #print(i)
            file_list.append(i)
            destination_files.append(str(extract_path_base) + os.path.splitdrive(i)[1])

            dir_list.append(os.path.split(i)[0])
            destination_dir.append(os.path.split(Path(str(extract_path_base) + os.path.splitdrive(i)[1]))[0])

    destination_dir = deduplicate_list(destination_dir)
    for d in destination_dir:
        if not Path(d).exists():
            os.makedirs(d)


    #print(destination_files[2])

    f.close()

    return destination_files, file_list


def split_relative_base_path(file, drive_letter):
    base_path = os.path.splitdrive(os.path.split(file)[0])[1]
    mount_drive = drive_letter.replace(":", "")
    base_path = mount_drive + str(base_path)
    relative_file_path = (str(file).replace(drive_letter + "\\", "")).replace("\\", "/")

    return relative_file_path, base_path


def main():
    parser = argparse.ArgumentParser(
        description='Collect the $UsnJrnl attributes and $MFT and save it to the destination_dir.')
    parser.add_argument('--drive', dest='drive_letter', action='store', type=str, default=None, required=True,
                        help='Logical drive to extract from (e.g., "F:")')
    parser.add_argument('--dest', dest='destination_dir', action='store', type=str, default=None, required=True,
                        help='Destination directory to extract files to.')
    parser.add_argument('--mft', action=argparse.BooleanOptionalAction,
                        help='Optional. Extracts $MFT.')
    parser.add_argument('--usnj', action=argparse.BooleanOptionalAction,
                        help='Optional. Extracts NTFS $UsnJrnl:$J, $UsnJrnl:$MAX and $LogFile.')
    parser.add_argument('--full_triage', action=argparse.BooleanOptionalAction,
                        help='Optional. Extracts a full triage of files. Implicitly includes other optional args.')
    args = parser.parse_args()

    start = time.perf_counter()
    print(f'{bcolors.WARNING}\
########################################################\n\
 _________     _____   __________ ___   _______________ \n\
 \_   ___ \   /  _  \  \______   \\   \ /   /\_   _____/ \n\
 /    \  \/  /  /_\  \  |       _/ \  \   /  |    __)_  \n\
 \     \____/    |    \ |    |   \  \    /   |        \ \n\
  \______  /\____|__  / |____|_  /   \__/   /_______  / \n\
         \/         \/         \/           @HurDFIR\/ \n\
########################################################{bcolors.ENDC}')

    physical_disk = convert_mount_to_disk(args.drive_letter)
    partition_handle = get_data_partition(physical_disk)

    mount_letter = args.drive_letter.replace(":", "")
    cwd = os.getcwd()
    extract_path_base = Path(cwd + "\\" + mount_letter)

    if not extract_path_base.exists():
        os.mkdir(extract_path_base)

    if args.mft:
        extract_file(r'$MFT', partition_handle, trailing_slash(str(args.drive_letter).replace(":", "")))

    if args.usnj:
        extract_usnj_attributes(partition_handle, trailing_slash(str(args.drive_letter).replace(":", "")))
        extract_file(r'$LogFile', partition_handle, trailing_slash(str(args.drive_letter).replace(":", "")))

    if args.full_triage:
        destination_files, source_files = list_files(file_list_file="file_list.txt", drive_letter=args.drive_letter)
        failed_files = copy_files(source_files)
        if failed_files:
            f = open(trailing_slash(str(extract_path_base)) + 'failed_files.txt', 'w')
            f.write("These files failed the normal extraction process. However, they may have been carved byte for byte into a new file. If this is the case, then the file's metadata cannot be trusted.\n\n")
            print(f"{bcolors.BOLD}[--] Trying to carve the failed files [--]{bcolors.ENDC}")
            for file in failed_files:
                try:
                    f.write(str(file) + "\n")
                    relative_file_path, base_path = split_relative_base_path(file, args.drive_letter)
                    extract_file(relative_file_path, partition_handle, trailing_slash(base_path))

                except Exception as e:
                    print(f"{bcolors.WARNING}[!] {e}{bcolors.ENDC}")
                    continue

            print(f"{bcolors.BOLD}[**] Finished to carving the failed files [**]{bcolors.ENDC}")

    if not (args.mft or args.usnj or args.full_triage):
        print("[!] You must specify one of --usnj, --mft, --full_triage. Exiting...")

    stop = time.perf_counter()
    print(f"{bcolors.HEADER}[--] Script took {stop - start:0.4f} seconds [--]{bcolors.ENDC}")


if __name__ == "__main__":
    main()
