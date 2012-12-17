import platform
from distutils.core import setup, Extension
import os, sys, glob
sys.path.append(os.pardir)

import smap
import py2exe
import py2exe2msi.command


# From http://www.py2exe.org/index.cgi/data_files
def find_data_files(source,target,patterns):
    """Locates the specified data-files and returns the matches
    in a data_files compatible format.

    source is the root of the source data tree.
        Use '' or '.' for current directory.
    target is the root of the target data tree.
        Use '' or '.' for the distribution directory.
    patterns is a sequence of glob-patterns for the
        files you want to copy.
    """
    if glob.has_magic(source) or glob.has_magic(target):
        raise ValueError("Magic not allowed in src, target")
    ret = {}
    for pattern in patterns:
        pattern = os.path.join(source,pattern)
        print pattern
        for filename in glob.glob(pattern):
            print filename
            if os.path.isfile(filename):
                targetpath = os.path.join(target,os.path.relpath(filename,source))
                path = os.path.dirname(targetpath)
                ret.setdefault(path,[]).append(filename)
    return sorted(ret.items())

# if platform.system() == 'Windows':
#   libs = ['bacnet', 'ws2_32', 'iphlpapi']
#   inc_dir = ['bacnet-stack-0.6.0/include', 'bacnet-stack-0.6.0/ports/win32', 'bacnet-stack-0.6.0/demo/object']
#   lib_path = 'bacnet-stack-0.6.0/lib'
# else:
#   libs = ['bacnet']
#   inc_dir = ['bacnet-stack-0.6.0/include', 'bacnet-stack-0.6.0/ports/linux', 'bacnet-stack-0.6.0/demo/object']
#   lib_path = 'bacnet-stack-0.6.0/lib'
# 
# bacnet_module = Extension('_bacnet',
#   sources=['bacnet.c', 'bacnet.i'],
#   libraries=libs,
#   library_dirs=[lib_path],
#   include_dirs=inc_dir)

class ServiceDesc:
  def __init__(self):
    self.version = "0.0.1"
    self.company_name = "University of California, Berkeley"
    self.copyright = "2012"
    self.name = "sMAP"
    self.description = 'sMAP 2.0 Driver Service'
    self.modules = ['smap2_service']
    self.cmdline_style='pywin32'

data_files = find_data_files(os.path.dirname(sys.modules['smap'].__file__),
                             '', ['schema\*.av'])
data_files.extend(find_data_files(os.path.dirname(__file__),
                                  '', ['dateutil/zoneinfo/*.tar.gz','db_ws', 'BACnet.ini']))
setup(
    name='bacnet',
    version='0.1',
    author='Andrew Krioukov',
    # ext_modules=[bacnet_module],
    data_files = data_files,
    # console=["scan.py", "bacnet_smap2.py", "print_list.py", "win32traceutil.py"],
    console = ["win32traceutil.py", "smap2_cmdline.py", "smap2_service.py"],
    service=[ServiceDesc()],
    zipfile=None,
    options = dict(
      py2exe = dict(
        compressed = 1,
        optimize = 2,
        bundle_files = 1,
        excludes = ['pywin', 'pywin.debugger', 'pywin.debugger.dbgcon',
                    'pywin.dialogs', 'pywin.dialogs.list'],
        dll_excludes = ['mswsock.dll', 'powrprof.dll'],
        # the type libraries are python wrappers around the COM types we're using
        typelibs = [
            ('{F8582D24-88FB-11D0-B850-00C0F0104305}', 0, 1, 0),
            ('{FAB7A1E3-3B79-4292-9C3A-DF39A6F65EC1}', 0, 5, 1)
            ]

      ),
    ),
)
