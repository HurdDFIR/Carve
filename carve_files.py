import os
import hashlib
from datetime import datetime as dt
from win32_set_timestamps import set_timestamps
from pywintypes import Time
import wmi
import re
import pytsk3
from pathlib import Path
import traceback
from wmi_vss import VSS
from carve_log import l
import glob
import csv

class File():
    def load(self, path, attribute=None, keep_dirstructure=False):
        if type(path) == list:
            file_path = Path(path[0])
            drive_letter = path[1]
        else:
            file_path = Path(path)

        try: exists = file_path.exists()
        except: exists = False
        try: is_file = file_path.is_file()
        except: is_file = True # Assume the file exists and may not be accessed because of permissions

        if exists:
            try:
                with file_path.open('rb') as f:
                    is_locked = False

            except (PermissionError, OSError):
                is_locked = True

            except Exception as e:
                l.error(f'Error: {e}\n{traceback.format_exc()}')
        else:
            is_locked = False

        if '$Extend\\$UsnJrnl' in str(file_path):
            try:
                attribute = file_path.name.split(':')[1]
                return CarveUsnJrnlFile(file_path, attribute=attribute)
            
            except IndexError as e:
                l.error(f"Error: {e}\nUsnJrnl glob incorrect. Expected format: C:\\$Extend\\$UsnJrnl:$J or C:\\$Extend\\$UsnJrnl:$Max")

        if str(file_path)[0:2] == '\\\\' and 'GLOBALROOT' not in str(file_path):
            return CarveNetworkFile(file_path, drive_letter=drive_letter)

        elif not exists:
            return CarveCreatedFile(file_path)

        elif is_file and is_locked:
            return CarveLockedFile(file_path)

        elif is_file and not is_locked:
            return CarveGenericFile(file_path)

        else:
            raise Exception("Not a valid file type")


class CarveFile():
    def __init__(self, path):
        self.path = Path(path)
        if "GLOBALROOT" not in str(self.path):
            if not self.path.is_absolute():
                self.path = self.path.resolve()
            self.uri = self.get_uri()
            self.root = self.get_root()
            self.drive_letter = self.get_drive_letter()
            self.directory = self.get_directory()
            self.directory_no_root = self.get_directory_no_root()
            self.path_no_root = self.get_path_no_root()
            self.mount_point = self.get_mount_point(drive_letter=self.drive_letter)

        self.exists = self.get_exists()
        self.is_file = self.get_is_file()
        self.name = self.get_name()
        self.extension = self.get_extension()
        self.directory = self.get_directory()
        self.size = self.get_size()
        self.modified_time = self.get_modified_time()
        self.created_time = self.get_created_time()
        self.accessed_time = self.get_accessed_time()
        self.sha1_hash = self.get_sha1_hash()      
    
    def delete(self):
        try:
            self.path.unlink()

        except FileNotFoundError:
            l.error(f"File doesn't exist: {self.path}")
        
        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')

    def update_attributes(self):
        if "GLOBALROOT" not in str(self.path):
            if not self.path.is_absolute():
                self.path = self.path.resolve()
            self.uri = self.get_uri()
            self.root = self.get_root()
            self.drive_letter = self.get_drive_letter()
            self.directory = self.get_directory()
            self.directory_no_root = self.get_directory_no_root()
            self.path_no_root = self.get_path_no_root()
            self.mount_point = self.get_mount_point(drive_letter=self.drive_letter)

        self.exists = self.get_exists()
        self.is_file = self.get_is_file()
        self.name = self.get_name()
        self.extension = self.get_extension()
        self.directory = self.get_directory()
        self.size = self.get_size()
        self.modified_time = self.get_modified_time()
        self.created_time = self.get_created_time()
        self.accessed_time = self.get_accessed_time()
        self.sha1_hash = self.get_sha1_hash()

    def get_mount_point(self, drive_letter):
        return drive_letter

    def get_root(self):
        self.root = self.path.anchor
        return self.root
    
    def get_name(self):
        self.name = self.path.name
        return self.name
    
    def get_extension(self):
        self.extension = self.path.suffix
        return self.extension   
    
    def get_path_no_root(self):
        self.path_no_root = str(self.path).replace(self.root, '')
        return self.path_no_root
    
    def get_directory_no_root(self):
        self.directory_no_root = str(self.directory).replace(self.root, '')
        return self.directory_no_root
    
    def get_directory(self):
        self.directory = self.path.parent
        return self.directory

    def get_uri(self):
        self.uri = self.path.as_uri()
        return self.uri

    def get_drive_letter(self):
        self.drive_letter = self.path.anchor[0]
        return self.drive_letter

    def get_data_partition(self):
        """
        A method to get the data partition from a physical disk. It converts
        the mount to a disk, then retrieves the partition table, and looks for
        the largest partition to get a handle for accessing the file system
        information. Returns the file system information handle if successful,
        otherwise logs an error and returns None.
        """
        physical_disk = self._convert_mount_to_disk()
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
                    partition_handle = pytsk3.FS_Info(
                        disk_handle, offset=(partition.start * 512))

            return partition_handle

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')
        
    def get_exists(self):
        self.exists = self.path.exists()
        return self.exists

    def get_is_file(self):
        self.is_file = self.path.is_file()
        return self.is_file

    def get_size(self):
        try:
            self.size = self.path.stat().st_size
            return self.size

        except FileNotFoundError:
            return 0

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')
            return None

    def get_sha1_hash(self):
        """
        Calculate the SHA-1 hash of the file specified by 'path'.
        If successful, return the SHA-1 hash. If an exception
        occurs, return None.
        """
        BLOCK_SIZE = 65536
        file_hash = hashlib.sha1()
        try:
            with open(self.path, "rb") as f:
                fb = f.read(BLOCK_SIZE)
                while len(fb) > 0:
                    file_hash.update(fb)
                    fb = f.read(BLOCK_SIZE)

                self.sha1_hash = file_hash.hexdigest()
                return self.sha1_hash

        except (FileNotFoundError, PermissionError, OSError):
            return None

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')
            return None

    def get_created_time(self):
        """
        Get the created time of the file.
        No parameters.
        Returns:
            Time: The created time of the file.
        """
        try:
            created = dt.fromtimestamp(self.path.stat().st_ctime)
            created = Time(created.replace(tzinfo=created.astimezone().tzinfo))
            return created

        except FileNotFoundError:
            return None

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')
            return None

    def get_modified_time(self):
        """
        Get the modified time of the file specified by the path.

        :return: Time object representing the modified time.
        """
        try:
            modified = dt.fromtimestamp(self.path.stat().st_mtime)
            modified = Time(modified.replace(
                tzinfo=modified.astimezone().tzinfo))
            return modified

        except FileNotFoundError:
            return None

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')
            return None

    def get_accessed_time(self):
        """
        Get the accessed time of the file specified by the path.

        Parameters:
            self (object): The object instance
            Returns:
            Time: The accessed time of the file
        """
        try:
            accessed = dt.fromtimestamp(self.path.stat().st_atime)
            accessed = Time(accessed.replace(
                tzinfo=accessed.astimezone().tzinfo))
            return accessed

        except FileNotFoundError:
            return None

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')
            return None

    def _convert_mount_to_disk(self):
            """
            A function to convert mountpoint to physical disk label, using WMI to
            find the physical drive mapping.
            """
            try:
                w = wmi.WMI()
                for drive in w.win32_LogicalDiskToPartition():
                    physical_disk_id = drive.Antecedent.deviceid
                    logical_disk_id = drive.Dependent.DeviceID

                    if logical_disk_id == (self.drive_letter + ':'):
                        s = re.compile('(Disk #)(\d)')
                        m = s.match(physical_disk_id)
                        physical_disk_number = m.group(2)
                        break

                physical_disk_string = "\\\\.\\PhysicalDrive" + \
                    str(physical_disk_number)

            except Exception as e:
                l.error(f'Error: {e}\n{traceback.format_exc()}')

            return physical_disk_string


class CarveCreatedFile(CarveFile):
    def __init__(self, path):
        super().__init__(path)

    def _set_timestamps(self, file: CarveFile):
        """
        Set file timestamps and update object attributes.
        Parameters:
            created: datetime object
                - the timestamp to set as the creation time
            modified: datetime object
                - the timestamp to set as the modification time
            accessed: datetime object
                - the timestamp to set as the access time
        Returns:
            None
        """
        set_timestamps(self.path, file.created_time,
                       file.accessed_time, file.modified_time)
        self.created_time = self.get_created_time()
        self.modified_time = self.get_modified_time()
        self.accessed_time = self.get_accessed_time()

    def create(self):
        try:
            self.path.touch()

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')


class CarveGenericFile(CarveFile):
    def __init__(self, path):
        super().__init__(path)

    def carve(self, dest_path, source_path=None, use_vss=False, partition_handle=None):
        """
        Copy the current file to the specified destination path and set
        timestamps.
        Args:
            dest_path: The destination path to which the file will be copied.
        Returns:
            The File object representing the copied file with updated
            timestamps.
        """
        if source_path == None:
            source_path = self.path

        dest_file = CarveCreatedFile(dest_path)
        try:
            O_BINARY = os.O_BINARY

        except:
            O_BINARY = 0
            
        READ_FLAGS = os.O_RDONLY | O_BINARY
        WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_BINARY
        BUFFER_SIZE = 128*1024

        try:
            bytes_written = 0
            if not os.path.exists(dest_file.directory):
                os.makedirs(dest_file.directory)

            input = os.open(str(source_path), READ_FLAGS)
            stat = os.fstat(input)
            output = os.open(str(dest_file.path), WRITE_FLAGS, stat.st_mode)
            for x in iter(lambda: os.read(input, BUFFER_SIZE), ""):
                if x == b'':
                    break
                bytes_written += os.write(output, x) 

        except PermissionError as e:
            pass

        finally:
            try: os.close(input)
            except Exception as e: l.error(f'Failed to close input file: {source_path}: {e}')
            try: os.close(output)
            except Exception as e: l.error(f'Failed to close output file: {dest_file.path}: {e}')

            dest_file._set_timestamps(self)
            dest_file.update_attributes()
            
            return dest_file


class CarveLockedFile(CarveGenericFile):
    def __init__(self, path):
        super().__init__(path)

    def carve(self, dest_path, use_vss=True, partition_handle=None):         
        try:
            dest_file = CarveCreatedFile(dest_path)

            if use_vss:
                vss_handle = VSS(self.root)
            else:
                vss_handle = None

            if not os.path.exists(dest_file.directory): 
                os.makedirs(dest_file.directory)
            
            if use_vss and vss_handle:
                source_path = vss_handle.path + os.sep + self.path_no_root

                source_file = File().load(source_path)
                self.sha1_hash = source_file.sha1_hash
                destination_file = source_file.carve(dest_file.path)

                if destination_file is None:
                    raise Exception("File not found in VSS snapshot. Defferring")
            
            else:
                use_vss = False

            if not use_vss:
                if partition_handle == None:
                    partition_handle = self.get_data_partition()

                file_handle = partition_handle.open(self.path_no_root.replace("\\", "/"))

                size = file_handle.info.meta.size

                with open(dest_file.path, 'wb') as out_file:
                    CHUNK_SIZE = 128*1024 
                    if size > CHUNK_SIZE:
                        pos = 0
                        first_iteration = True
                        while pos < size:
                            remainder = size - pos
                            if remainder > CHUNK_SIZE:
                                buffer = file_handle.read_random(pos, CHUNK_SIZE)
                                
                                tmp_buf = buffer
                                if tmp_buf.lstrip(b'\x00') == b'' and first_iteration:
                                    # This checks for sparse/empty files and ignores the leading zeros
                                    pos += len(buffer)
                                    continue

                                out_file.write(buffer)
                                pos += CHUNK_SIZE
                                first_iteration = False
                            else:
                                out_file.write(file_handle.read_random(pos, remainder))
                                pos += remainder

                    else:
                        try:
                            out_file.write(file_handle.read_random(0, size))
                        
                        except OSError as e:
                            pass

            dest_file._set_timestamps(self)
            dest_file.update_attributes()

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')

        finally:
            if vss_handle and use_vss:
                vss_handle.delete()

            if dest_file:
                return dest_file


class CarveUsnJrnlFile(CarveFile):
    def __init__(self, path, attribute):
        super().__init__(path)
        self.attribute = attribute

    def carve(self, dest_path, partition_handle=None):
        if partition_handle == None:
            partition_handle = self.get_data_partition()

        dest_path = Path(str(dest_path))
        dest_name = str(dest_path.name).replace(':','_')
        dest_parent = str(dest_path.parents[0])
        dest_path = Path(dest_parent + os.sep + dest_name)

        #dest_path = Path(str(dest_path).replace(':','_'))
        dest_file = CarveCreatedFile(dest_path)

        UsnJrnl = partition_handle.open(self.path_no_root.replace("\\", "/"))

        for attribute in UsnJrnl:
            if attribute.info.name == bytes(self.attribute, 'utf-8'):
                selected_attribute = attribute
        
        dest_file_UsnJrnl_attribute = self._carve_attribute(attribute=selected_attribute, UsnJrnl=UsnJrnl, dest_file=dest_file)
        
        dest_file_UsnJrnl_attribute.update_attributes()

        return dest_file_UsnJrnl_attribute
    
    def _carve_attribute(self, attribute, UsnJrnl, dest_file):
        if not os.path.exists(dest_file.directory): 
                os.makedirs(dest_file.directory)

        size = attribute.info.size
        with open(dest_file.path, 'wb') as out_file:
            CHUNK_SIZE = 128*1024
            if size > CHUNK_SIZE:
                pos = 0
                sparse = True
                while pos < size:
                    remainder = size - pos
                    if remainder > CHUNK_SIZE:
                        buffer = UsnJrnl.read_random(pos, CHUNK_SIZE, attribute.info.type, attribute.info.id)
                        
                        tmp_buf = buffer
                        if tmp_buf.lstrip(b'\x00') == b'' and sparse:
                            # This checks for sparse attributes and ignores the leading zeros
                            pos += len(buffer)
                            continue
                        
                        out_file.write(buffer)
                        pos += CHUNK_SIZE
                        sparse = False

                    else:
                        out_file.write(UsnJrnl.read_random(pos, remainder, attribute.info.type, attribute.info.id))
                        pos += remainder
            
            else:
                out_file.write(UsnJrnl.read_random(0, size, attribute.info.type, attribute.info.id))  

        return dest_file


class CarveNetworkFile(CarveGenericFile):
    def __init__(self, path, drive_letter):
        super().__init__(path)
        self.mount_point = drive_letter
        self.root = self.root.replace('\\\\', '')
        self.drive_letter = ''


class CarveFiles():
    def __init__(self, file_paths: list, keep_dirstructure=False):
        if issubclass(type(file_paths[0]), CarveFile):
            self.files = file_paths
        else:
            self.files = self.make_carvefiles(file_paths)

        self.drive_roots = self._get_drive_roots()
        self.keep_dirstructure = keep_dirstructure

    def carve_files(self, dest_root, use_vss=True):
        failed_files = []
        vss_handles = []
        carve_dest_files = []
        carve_locked_files = []
        carve_generic_files = []
        carve_usnjrnl_files = []
        carve_network_files = []
        try:
            for carve_file in self.files:
                if type(carve_file) == CarveLockedFile:
                    carve_locked_files.append(carve_file)
                elif type(carve_file) == CarveGenericFile:
                    carve_generic_files.append(carve_file)
                elif type(carve_file) == CarveNetworkFile:
                    carve_network_files.append(carve_file)
                elif type(carve_file) == CarveUsnJrnlFile:
                    carve_usnjrnl_files.append(carve_file)
            
            if carve_generic_files: 
                l.debug("CarveGenericFiles found!")
                for generic_file in carve_generic_files:
                    l.info(f'Carving Generic File : {generic_file.path}')
                    try:
                        if self.keep_dirstructure:
                            dest_path = dest_root + os.sep + generic_file.drive_letter + os.sep + generic_file.path_no_root
                        else:
                            dest_path = dest_root + os.sep + generic_file.name
                        
                        file = generic_file.carve(dest_path=dest_path)
                        carve_dest_files.append(file)
                    
                    except Exception as e:
                        l.warning(f'Deferring:  {generic_file.path}')
                        failed_files.append(generic_file)
            
            if carve_network_files:
                l.debug("CarveNetworkFiles found!")
                for network_file in carve_network_files:
                    l.info(f'Carving Network File: {network_file.path}')
                    try:
                        if self.keep_dirstructure:
                            dest_path = dest_root + os.sep + str(network_file.path)
                        else:
                            dest_path = dest_root + os.sep + str(network_file.name)
                        
                        carve_dest_files.append(network_file.carve(dest_path=dest_path))
                    
                    except Exception as e:
                        l.error(f'Error: {e}\n{traceback.format_exc()}')
                        #failed_files.append(network_file)

            if carve_locked_files:
                l.debug("CarveLockedFiles found!")
                if use_vss:
                    l.debug('Attempting to build VSS handles for necessary drives')
                    for drive_root in self.drive_roots:
                        try:
                            vss_handles.append(VSS(drive_root))
                            l.info(f'VSS handle found for {drive_root}')

                        except Exception as e:
                            l.error(f'Error with VSS handle: {e}')
                            l.critical('Disabling VSS locked file carving')
                            use_vss = False

                if use_vss:
                    try:
                        for vss_handle in vss_handles:
                            l.debug(f'Found VSS handle {vss_handle.path}')

                        for locked_file in carve_locked_files:
                            l.info(f'Carving Locked File: {locked_file.path}')
                            for vss_handle in vss_handles:
                                if str(vss_handle._drive_root).lower() == str(locked_file.root).lower():
                                    source_path = vss_handle.path + os.sep + locked_file.path_no_root
                                    
                                    if self.keep_dirstructure:
                                        dest_path = dest_root + os.sep + locked_file.drive_letter + os.sep + locked_file.path_no_root
                                    else:
                                        dest_path = dest_root + os.sep + locked_file.name

                                    source_file = File().load(source_path)

                                    if type(source_file) == CarveGenericFile:
                                        carve_dest_files.append(source_file.carve(dest_path=dest_path))
                                    else:
                                        l.warning(f'Deferring:  {locked_file.path}')
                                        failed_files.append(locked_file)

                    except Exception as e:
                        l.warning(f'Deferring:  {locked_file.path}')
                        failed_files.append(locked_file)    

                else:
                    l.critical(f'VSS carving disabled. This is slower..')
                    try:
                        partition_handles = {}
                        for locked_file in carve_locked_files:
                            l.info(f'Carving Locked File (no VSS): {locked_file.path}')
                            if locked_file.drive_letter not in partition_handles.keys():
                                l.debug(f'Building partition handle for {locked_file.drive_letter}')
                                partition_handles[locked_file.drive_letter] = locked_file.get_data_partition()

                            if self.keep_dirstructure:
                                dest_path = dest_root + os.sep + locked_file.drive_letter + os.sep + locked_file.path_no_root
                            else:
                                dest_path = dest_root + os.sep + locked_file.name

                            if type(locked_file) == CarveLockedFile:
                                carve_dest_files.append(locked_file.carve(dest_path=dest_path, use_vss=False, partition_handle=partition_handles[locked_file.drive_letter]))

                            else:
                                l.critical(f"{locked_file.path} is not a CarveLockedFile, it is a {type(locked_file)}. This is not an efficient way to carve this file, but it works.")
                                carve_dest_files.append(locked_file.carve(dest_path=dest_path, use_vss=False, partition_handle=partition_handles[locked_file.drive_letter]))
                    
                    except Exception as e:
                            l.warning(f'Deferring:  {locked_file.path}')
                            failed_files.append(locked_file) 

            if failed_files:
                try:
                    l.critical('Carve is attempting a low level copy of deferred files')
                    partition_handles = {}
                    success_files = []
                    for file in failed_files:
                        l.info(f'Carving Failed File: {file.path}')
                        if locked_file.drive_letter not in partition_handles.keys():
                                partition_handles[locked_file.drive_letter] = locked_file.get_data_partition()
                        
                        if self.keep_dirstructure:
                            dest_path = dest_root + os.sep + file.drive_letter + os.sep + file.path_no_root
                        else:
                            dest_path = dest_root + os.sep + file.name

                        if type(file) == CarveLockedFile:
                            carve_dest_files.append(file.carve(dest_path=dest_path, use_vss=False, partition_handle=partition_handles[locked_file.drive_letter]))

                        else:
                            l.critical(f"{file.path} is not a CarveLockedFile, it is a {type(file)}. This is not an efficient way to carve this file, but it works.")
                            carve_dest_files.append(file.carve(dest_path=dest_path, use_vss=False, partition_handle=partition_handles[locked_file.drive_letter]))

                        success_files.append(file)
                    
                    for file in success_files:
                        failed_files.remove(file)
                
                except Exception as e:
                        l.error(f'Error: {e}\n{traceback.format_exc()}')

            if carve_usnjrnl_files:
                l.debug('CarveUsnJrnlFile found!')
                for usnjrnl in carve_usnjrnl_files:
                    if self.keep_dirstructure:
                        dest_path = dest_root + os.sep + usnjrnl.drive_letter + os.sep + usnjrnl.path_no_root
                    else:
                        dest_path = dest_root + os.sep + usnjrnl.name
                    
                    l.info(f'Carving UsnJrnl attrubute: {usnjrnl.path}')
                    carve_dest_files.append(usnjrnl.carve(dest_path=dest_path))            

        except Exception as e:
            l.error(f'Error: {e}\n{traceback.format_exc()}')

        finally:
            for vss_handle in vss_handles:
                l.debug(f"Cleaning up VSS Handle: {vss_handle.path}")
                vss_handle.delete()

            return carve_dest_files, failed_files

    def make_carvefiles(self, file_paths):
        carve_files = []
        errors = []

        for file in file_paths:
            try:
                l.debug(f'Building CarveFile: {file}')
                f = File().load(file)

                carve_files.append(f)
            
            except Exception as e:
                l.error(f'Error: {file} | {e}')
                errors.append(file)

        return carve_files
    
    def _get_drive_roots(self):
        drive_roots = []
        for file in self.files:
            if type(file) == CarveLockedFile:
                drive_roots.append(file.root.lower())

        drive_roots = list(set(drive_roots))
        return drive_roots


class TriageListFile:
    def __init__(self, glob_list_file: Path=None, file_paths=None):
        self.glob_list_file = glob_list_file
        self.file_paths = file_paths
        self.file_list = self.get_file_list()

    def get_file_list(self):
        file_list = []
        if self.file_paths:
            for file in self.file_paths:
                files = glob.glob(file, recursive=True)
                for f in files:
                    fpath = Path(f)              
                    if fpath.exists() and fpath.is_file():
                        file_list.append(fpath)
                    else:
                        continue
        
        if self.glob_list_file:
            with open(self.glob_list_file, 'r', encoding='utf-8') as triage_globs:
                l.debug(f'Building triage file list from {self.glob_list_file}')
                
                for line in triage_globs:
                    if line.strip()[0] == '#':
                        continue

                    if '$UsnJrnl' in line.strip():
                        file_list.append(line.strip())
                        continue
                    
                    if line.strip()[0:4] == '\\\\**':
                        # Unknown Network share
                        network_drives = self.get_network_drives()
                        pattern = (line.strip().split('\\\\**')[1]).lower()

                        if pattern[0] == '\\':
                            pattern = (pattern[1:]).lower()

                        for drive in network_drives:
                            network_path = Path(f"{drive[0]}\\").resolve()
                            files = network_path.glob(pattern)
                            for file in files:
                                if file.exists() and file.is_file():
                                    file_list.append([file, drive[1][0]])
                    
                    elif line.strip()[0:2] == '\\\\':
                        # Known network Network share
                        network_drives = self.get_network_drives()
                        pattern = (line.strip()).lower()

                        for drive in network_drives:
                            network_path = str(Path(f"{drive[0]}\\").resolve()).lower()
                            if network_path == pattern[0:len(network_path)]:
                                g = str(pattern).replace(network_path, '')

                            files = Path(network_path).resolve().glob(g)
                            for file in files:
                                if file.exists() and file.is_file():
                                    file_list.append([file, drive[1][0]])
                    
                    else:
                        files = glob.glob(line.strip(), recursive=True)

                        for file in files:
                            try:
                                p = Path(file).resolve()
                                if p.exists() and p.is_file():
                                    file_list.append(p)
                            
                            except FileNotFoundError as e:
                                l.error(f"File doesn't exist: {e}")
                                continue 

        return file_list
    
    def get_network_drives(self):
        network_drives =  []
        mounted_drives = self._get_mounted_drives()
        for drive in mounted_drives:
            path = Path(f'{drive}\\').resolve()
            if str(path)[0:2] == '\\\\':
                network_drives.append([path,drive])

        return network_drives

    def _get_mounted_drives(self):
        c = wmi.WMI()
        drives = [wmi_object.deviceID for wmi_object in c.Win32_LogicalDisk()]
        
        return drives
    

class Sha1HashFile:
    def __init__(self, dest_root=None, destination_files=None, file_name='Sha1Hashes.csv'):
        self.dest_root = dest_root
        self.destination_files = destination_files
        self.file_name = file_name
        self.path = Path(self.dest_root + os.sep + self.file_name).resolve()
        self.sha1_hashes = self.get_sha1_hashes()

    def get_sha1_hashes(self):
        sha1_hashes = {}
        for file in self.destination_files:
            if issubclass(type(file), CarveFile):
                sha1_hashes[file.path] = [str(file.sha1_hash), str(file.created_time), str(file.modified_time), str(file.accessed_time)]
            else:
                l.warning(f'{file}|{file.path} is not a CarveFile')
                continue

        return sha1_hashes
    
    def write(self):
        with open(self.path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['FilePath', 'Sha1Hash','CreatedTime', 'ModifiedTime', 'AccessedTime']
            csv_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            csv_writer.writeheader()
            for path, sha1_hash in self.sha1_hashes.items():
                csv_writer.writerow({'FilePath': str(path), 'Sha1Hash': sha1_hash[0], 'CreatedTime': sha1_hash[1], 'ModifiedTime': sha1_hash[2], 'AccessedTime': sha1_hash[3]})