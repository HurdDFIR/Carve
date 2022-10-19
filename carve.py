 #!/usr/bin/python

import pytsk3
import wmi
import re
import argparse

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
    partition_table = pytsk3.Volume_Info(disk_handle)

    for partition in partition_table:
        if b'Basic data partition' in partition.desc:
            partition_handle = pytsk3.FS_Info(disk_handle, offset=(partition.start*512))

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
            print("[-] Extracting: %s" % (attribute.info.name.decode()))
            extract_file_attributes(usnj, attribute, destination_dir)
            print(f"{bcolors.OKGREEN}[*] Finished extracting: %s{bcolors.ENDC}" % (attribute.info.name.decode()))

        if attribute.info.name == b'$Max':
            print("[-] Extracting: %s" % (attribute.info.name.decode()))
            extract_file_attributes(usnj, attribute, destination_dir)
            print(f"{bcolors.OKGREEN}[*] Finished extracting: %s{bcolors.ENDC}" % (attribute.info.name.decode()))


def extract_file_attributes(file, attribute, destination_dir):
    """
    Extracts a file's attributes
    :param file:
    :param attribute:
    :param destination_dir:
    :return:
    """
    out_file = open(destination_dir + attribute.info.name.decode(), 'wb')
    size = attribute.info.size
    file_data = file.read_random(0, size, attribute.info.type, attribute.info.id)
    out_file.write(file_data)
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
    file_data = file_handle.read_random(0, file_handle.info.meta.size)
    print("[-] Extracting: %s" % (file_handle.info.name.name.decode()))
    out_file.write(file_data)
    print(f"{bcolors.OKGREEN}[*] Finished extracting: %s{bcolors.ENDC}" % (file_handle.info.name.name.decode()))
    out_file.close()


def trailing_slash(string):
    """
    Takes a sting and adds a trailing slash, if it does not have it.
    :param string:
    :return: an edited string with a trailing slash
    """
    if not string.endswith('\\'):
        string += '\\'

    return string


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

    if args.mft:
        extract_file(r'$MFT', partition_handle, trailing_slash(args.destination_dir))

    if args.usnj:
        extract_usnj_attributes(partition_handle, trailing_slash(args.destination_dir))
        extract_file(r'$LogFile', partition_handle, trailing_slash(args.destination_dir))

    if args.full_triage:
        print("[!] The --full_triage option is not supported, yet.")

    if not (args.mft or args.usnj or args.full_triage):
        print("[!] You must specify one of --usnj, --mft, --full_triage. Exiting...")


if __name__ == "__main__":
    main()
