import io
import os
from setuptools import find_packages, setup


DESCRIPTION = 'This application will store cat sponsorship information.'

here = os.path.abspath(os.path.dirname(__file__))
try:
    with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = '\n' + f.read()
except FileNotFoundError:
    long_description = DESCRIPTION

setup(
    name='sponsorcat',
    version='1.2.1',
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='amberh',
    python_requires='>=3.6.0',
    url='https://github.com/amberheilman/sponsor-cat',
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    install_requires=['flask',
                      'flask-cors',
                      'flask-login',
                      'Flask-WTF',
                      'psycopg2',
                      'waitress'],
    include_package_data=True,
    license='MIT',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Framework :: Flask',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
)
