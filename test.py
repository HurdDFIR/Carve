
import pytsk3

disk_handle = pytsk3.Img_Info("\\\\.\\physicaldrive0")
partition_table = pytsk3.Volume_Info(disk_handle)

largest = 0
partition_id = None
for partition in partition_table:
    if partition.len > largest:
        largest = partition.len
        partition_id = partition.addr
        print(f"New largest part: len={largest}, id={partition_id}")

    else:
        continue

for partition in partition_table:
    if partition.addr == partition_id:
        print(f"Trying to mount: len={partition.len}, desc={partition.desc}, slot_num={partition.slot_num}, table_num={partition.table_num}, flags={partition.flags}, addr={partition.addr}")
        partition_handle = pytsk3.FS_Info(disk_handle, offset=(partition.start * 512))
        print(f"success: {partition_handle}")


