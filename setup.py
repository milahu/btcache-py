#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="btcache",
    version="0.1.0",
    description="a caching BitTorrent proxy for hidden seeders, written in Python",
    author="Milan Hauth",
    author_email="milahu@gmail.com",
    url="https://github.com/milahu/btcache-py",
    python_requires=">=3.0",
    py_modules=["btcache"],
    install_requires=[
        "requests>=2.0.0",
        "libtorrent>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "btcache=btcache:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
