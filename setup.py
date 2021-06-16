from setuptools import Extension, setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize([
        Extension("pywireguard", [
        "src/pywireguard/wireguard.pyx",
        "src/pywireguard/c_lib/wireguard.c"
        ])
    ])
)
