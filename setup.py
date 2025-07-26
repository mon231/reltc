import setuptools
from pathlib import Path


CURRENT_FOLDER = Path(__file__).parent
README_PATH = CURRENT_FOLDER / 'README.md'

setuptools.setup(
    name = "reltc",
    version = "1.1.1",
    author = "Ariel Tubul",
    packages = setuptools.find_packages(),
    long_description=README_PATH.read_text(),
    install_requires = ['PyQt5'],
    long_description_content_type='text/markdown',
    url = "https://github.com/mon231/reltc/",
    description = "Linux TC command-generator",
    entry_points = {'gui_scripts': ['reltc=reltc.main:main']}
)
