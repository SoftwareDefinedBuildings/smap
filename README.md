
sMAP 'unitoftime' branch
========================

This branch is the opposite of production ready. Nevertheless it passes unit tests that don't require operators. Any non-trivial operators will fail as that code has not been written yet (I've been prioritising writing unit tests that pass on the main branch first)

In order for the archiver to work, you need to be running the 'adaptive' branch of readingdb. Which is also not production ready. (We like to have fun here).


# SMAP

## Getting Started

### Installation

#### Python

To setup a clean environment, create a new python virtual environment with:

    virtualenv venv

Before proceeding with installation, make sure you've sourced the virtual environment with `source venv/bin/activate`.

You must install the dependencies listed in `requirements.txt` before installing smap. Do this by issuing the following:

    pip install -r osx_requirements.txt

After the dependencies are installed, run the installation:

    python setup.py install

