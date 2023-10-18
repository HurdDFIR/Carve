
>     _________     _____   __________ ___   _______________ 
>     \_   ___ \   /  _  \  \______   \\   \ /   /\_   _____/
>     /    \  \/  /  /_\  \  |       _/ \  \   /  |    __)_  
>     \     \____/    |    \ |    |   \  \    /   |        \ 
>      \______  /\____|__  / |____|_  /   \__/   /_______  / 
>             \/         \/         \/           @HurDFIR\/ 

carve.py is a tool to help collect files from a mounted file system. You can collect $UsnJrnl:$J, $MFT, other locked system files as as well as regular files.

## Installation

The easiest way to install the dependencies is with:
> pip install -r requirements.txt

## How to
> usage: carve.py [-h] -d DRIVE_LETTER -o OUT_DIR [--mft | --no-mft] [--usnj | --no-usnj] [-t | --triage | --no-triage] [-f FILE_LIST]
                [-k | --keep-dirstruct | --no-keep-dirstruct] [-v | --verbose | --no-verbose]

Arguments | Description
--- | ---
-h, --help | Show help message and exit
-d, --drive | Logical drive to extract from (e.g., "F:")
-o, --out | Destination directory to extract files to.
--mft, --no-mft | Optional. Extracts $MFT.
--usnj, --no-usnj | Optional. Extracts NTFS $UsnJrnl:$J, $UsnJrnl:$MAX and $LogFile.
-t, --triage | Optional. Extracts a triage of files based upong a list provided by the --triage-filter argument. 
-f, --triage-filter | Required if --triage is used. Provides the path to a list of files to extract. If standard extraction fails, then it carves the file byte for byte into a new one. 
-k, --keep-dirstruct | Optional. Keeps the source directory stucture.
-v, --verbose | Default is False. Enable for debugg logging.


## Disclaimer

This tool does not retain ALL of the attributes from the original files. It does it's best to keep metadata such as timestamps. But, some ACL and other information may also be lost. Carve has two functions that will collect files/data. The "normal", or default attempt, will try to keep as much metadata as possible. 

If any of the files fail, then Carve will "carve" them byte for byte into a new file. This will not retain any of the metadata. This is always true for locked system files and alternate data streams. 

## License

MIT
