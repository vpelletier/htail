from setuptools import setup
from os.path import join, dirname
import sys

description = open(join(dirname(__file__), 'README.rst')).read()
setup(
    name='htail',
    version='1.3',
    author='Vincent Pelletier',
    author_email='plr.vincent@gmail.com',
    description=next(x for x in description.splitlines() if x.strip()),
    long_description=description,
    url='http://github.com/vpelletier/htail',
    license='GPL 2+',
    platforms=['any'],
    classifiers=[
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities',
    ],
    py_modules=['htail'],
    entry_points = {
        'console_scripts': [
            'htail=htail:main',
        ],
    },
    zip_safe=True,
    use_2to3=sys.version_info >= (3, ),
)
