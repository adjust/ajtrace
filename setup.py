from setuptools import setup

setup(
    name='ajtrace',
    version='0.1dev',
    packages=['ajtrace', 'ajtrace.ebpf_modules'],
    url='https://github.com/adjust/ajtrace',
    author='Ildar Musin',
    entry_points={
        'console_scripts': ['ajtrace = ajtrace.ajtrace:main']
    }
)
