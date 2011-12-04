# Called from scons with appropriate python version
import sys
from distutils.core import setup
sys.dont_write_bytecode = True
from regfi_version import REGFI_VERSION
sys.dont_write_bytecode = False

setup(name='pyregfi', version=REGFI_VERSION, package_dir={'':'python'}, packages=['pyregfi'])
