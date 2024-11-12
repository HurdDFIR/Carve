from carve_log import l, logger_setup, bcolors, ColorCodes
from carve_files import CarveFiles, TriageListFile, Sha1HashFile
import argparse
import time

# TODO: build hash matching function
def main():
    __version__ = '2.0.0'
    __author__ = 'Stephen Hurd | @HurdDFIR'
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='CARVE is a tool that collects files from a filesystem based on a list of globs. CARVE supports the extraction of generic files, locked files, system files, files on network mounted drives as well as UsnJrnl attribute extraction.',
        epilog=f'v{__version__} | Author: {__author__}')
    required = parser.add_argument_group(title='Required', description='One of -t or -f must be specified.')
    triage_or_file = required.add_mutually_exclusive_group(required=True)
    triage_or_file.add_argument('-t', dest='triage_file', action='store', type=str, default=None, required=False,
                        help='Text file that stores a list of globs to collect.')
    triage_or_file.add_argument('-f', dest='carve_files', metavar='FILE_LIST', action='extend', nargs='+', type=str, default=None, required=False,
                        help='Space separated list of files to collect with Carve. This supports glob/wildcard formats.')
    required.add_argument('-o', dest='output_root', action='store', type=str, default=None, required=True,
                        help='Destination base directory to carve files into.')
    
    optional = parser.add_argument_group('Optional')
    optional.add_argument('-l', dest='log_file', action='store', type=str, default=None,
                        help='Log file name.')
    optional.add_argument('-k', '--keep_structure', dest='keep_structure', action='store_true', default=False,
                        help='Preserves the original directory stucture.')
    optional.add_argument('-v','--verbose', action='store_true', default=False,
                        help='Enable for debugg logging.')
    optional.add_argument('-q','--quiet', action='store_true', default=False,
                        help='Quiet logging. Writes full logs to the log file if available. Will still display error messages and warnings in the console.')
    optional.add_argument('--novss', dest='use_vss', action='store_false', default=True,
                        help='Turns off the usage of VSS for collecting locked files. The alternative is a low level copy that takes longer.')
    optional.add_argument('--remove_base_root', dest='remove_base_root', action='store', default=None,
                        help='Use this option if you want to remove a specifc prefix from the output path. E.g., Carving the file D:\\triage\\C\\windows\\system32\\winevt\\security.evtx will output to output\\d\\triage\\c\\windows\\system32\\winevt\\security.evtx. You can enter a value of D:\\triage to remove this from the output path, resulting in an output path of output\\C\\windows\\system32\\winevt\\security.evtx')

    args = parser.parse_args()

    start = time.perf_counter()

    print(f'{bcolors.WARNING}\
########################################################\n\
 _________     _____   __________ ___   _______________ \n\
 \_   ___ \   /  _  \  \______   \\\\  \ /   /\_   _____/ \n\
 /    \  \/  /  /_\  \  |       _/ \  \   /  |    __)_  \n\
 \     \____/    |    \ |    |   \  \    /   |        \ \n\
  \______  /\____|__  / |____|_  /   \__/   /_______  / \n\
         \/         \/         \/          @HurdDFIR\/ \n\
########################################################{bcolors.ENDC}')
    #print(args)
    if args.log_file:
        log_file = args.output_root + '\\' + args.log_file
    else:
        log_file = None
    logger_setup(verbose=args.verbose, quiet=args.quiet, log_file=log_file)

    l.critical('Carve is initializing..')
    
    if args.triage_file:
        triage_list = TriageListFile(glob_list_file=args.triage_file)

    elif args.carve_files:
        triage_list = TriageListFile(file_paths=args.carve_files)

    if not triage_list:
        l.error('Triage list is empty. No files to carve.')
        exit()

    dest_files, failed_files = CarveFiles(file_paths=triage_list.file_list,keep_dirstructure=args.keep_structure, remove_base_root=args.remove_base_root).carve_files(
            dest_root=args.output_root, use_vss=args.use_vss)

    if dest_files:
        sha1_file = Sha1HashFile(dest_root=args.output_root, destination_files=dest_files)
        l.debug(f'Writing Sha1HashFile to {sha1_file.path}')
        sha1_file.write()

    if failed_files:
        l.critical(f'Failed to carve files:')
        l.critical(f'========================')
        for file in failed_files:
            l.critical(f'\t{file.path}')

    stop = time.perf_counter()
    print(f"Carve took {stop - start:0.6f} seconds")

if __name__ == "__main__":
    main()
