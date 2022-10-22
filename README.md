
>     _________     _____   __________ ___   _______________ 
>     \_   ___ \   /  _  \  \______   \\   \ /   /\_   _____/
>     /    \  \/  /  /_\  \  |       _/ \  \   /  |    __)_  
>     \     \____/    |    \ |    |   \  \    /   |        \ 
>      \______  /\____|__  / |____|_  /   \__/   /_______  / 
>             \/         \/         \/           @HurDFIR\/ 

Carve is a easy way to carve NTFS files such as $MFT and $UsnJrnl attributes from a mounted image or live disk drive. Carve also has the capability to create a triage collection from the target disk drive.  

## Installation

The easiest way to install the dependencies is with:
> pip install -r requirements.txt

## How to
> usage: carve.py [-h] --drive DRIVE_LETTER --dest DESTINATION_DIR [--mft | --no-mft] [--usnj | --no-usnj]
                [--full_triage | --no-full_triage]

Arguments | Description
--- | ---
-h, --help | Show help message and exit
--drive | Logical drive to extract from (e.g., "F:")
--dest | Directory to extract files to.
--mft, --no-mft | Optional. Extracts $MFT.
--usnj, --no-usnj | Optional. Extracts NTFS $UsnJrnl:$J, $UsnJrnl:$MAX and $LogFile.
--full_triage, --no-full_triage | Optional. Extracts a full triage of files.

##Disclaimer

This tool does not retain ALL of the attributes from the original files. It does it's best to keep metadata such as timestamps. But, some ACL and other information may also be lost. Carve has two functions that will collect files/data. The "normal" or default attempt, will try to keep as much metadata as possible. 

If any of the files fail, then Carve will "carve" them byte for byte into a new file. This will not retain any of the metadata. This is always true for locked system files and alternate data streams. 

## License

MIT
