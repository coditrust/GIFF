from setuptools import setup, find_packages

setup(
    name='giff',
    version='0.1.0',
    author='Anthony Dessiatnikoff',
    description='This project allows to get information from vulnerable systems using LFI',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    py_modules=['giff'],
    url='https://github.com/coditrust/GIFF',
    packages=find_packages(),
    install_requires=[
        'requests',
        'colorama',
    ],
    entry_points={
        'console_scripts': [
            'giff=giff:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)

