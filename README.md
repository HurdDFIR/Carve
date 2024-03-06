
>     _________     _____   __________ ___   _______________ 
>     \_   ___ \   /  _  \  \______   \\   \ /   /\_   _____/
>     /    \  \/  /  /_\  \  |       _/ \  \   /  |    __)_  
>     \     \____/    |    \ |    |   \  \    /   |        \ 
>      \______  /\____|__  / |____|_  /   \__/   /_______  / 
>             \/         \/         \/          @HurdDFIR\/ 

CARVE is a tool that collects files from a filesystem based upon a supplied list of globs. CARVE supports the extraction of Windows generic files, locked files, system files, files on network mounted drives as well as UsnJrnl attribute extraction.

This tool utilizes Windows volume shadow copies (VSS) to gain access to some locked files. If the VSS service is disabled, carve will enable it and return it to the disabled state after it is done. Carve will clean up and delete any VSS volumes it creates. This usage may be turned off with the `--novss` option and functionality will still continue, but slower. 

Sleuthkit python bindings are used to gain access for low level copies (whenever required). This is slower than using VSS volumes. 

Carve is able to identify the \$UsnJrnl:\$J attriute and accuratley extract the data runs to a file. You will need to use a triage file with the following statement to target this attribute:

    C:\$Extend\$UsnJrnl:$J

This will save the file to the output directory with a file name of `Usnjrnl_J`

## Installation

The easiest way to install the dependencies is with:

    pip install -r requirements.txt

## Syntax
    usage: carve.py [-h] (-t TRIAGE_FILE | -f FILE_LIST [FILE_LIST ...]) -o OUTPUT_ROOT [-l LOG_FILE] [-k] [-v] [-q] [--novss]

    CARVE is a tool that collects files from a filesystem based on a list of globs. CARVE supports the extraction of generic files, locked files, system files, files on network mounted drives
    as well as UsnJrnl attribute extraction.

    options:
    -h, --help            show this help message and exit

    Required:
    One of -t or -f must be specified.

    -t TRIAGE_FILE        Text file that stores a list of globs to collect. (default: None)
    -f FILE_LIST [FILE_LIST ...]
                            Space separated list of files to collect with Carve. This supports glob/wildcard formats. (default: None)
    -o OUTPUT_ROOT        Destination base directory to carve files into. (default: None)

    Optional:
    -l LOG_FILE           Log file name. (default: None)
    -k, --keep_structure  Preserves the original directory stucture. (default: False)
    -v, --verbose         Enable for debugg logging. (default: False)
    -q, --quiet           Quiet logging. Writes full logs to the log file if available. Will still display error messages and warnings in the console. (default: False)
    --novss               Turns off the usage of VSS for collecting locked files. The alternative is a low level copy that takes longer. (default: True)

    v2.0.0 | Author: Stephen Hurd | @HurdDFIR

## Examples
Simple usage with triage file:

    python3 .\carve.py -t triage_globs.txt -o .\output

Simple usage with CLI glob:

    python3 .\carve.py -f 'C:\$Extend\$UsnJrnl:$J' 'C:\windows\system32\config\**' 'C:\users\*\appdata\**' -o .\output

Not using VSS:
    
    python3 .\carve.py -t triage_globs.txt -o .\output --novss

With a log file/verbose:

    python3 .\carve.py -t triage_globs.txt -o .\output -l carve_debug.log -v


## Disclaimer

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## License

MIT
