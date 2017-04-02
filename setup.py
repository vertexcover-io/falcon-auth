"""
Setup script.
"""

from setuptools import setup


setup(
    author='Ritesh Kadmawala',
    author_email='ritesh@loanzen.in',
    description='falcon-auth',
    download_url='',
    install_requires=[
        'falcon',
        'pyjwt'
    ],
    license='MIT',
    name='falcon-auth',
    packages=[
        'falcon_auth',
    ],
    scripts=[],
    test_suite='tests',
    tests_require=[
        'codecov>=2.0.3,<3.0.0',
        'coverage>=4.0.3,<5.0.0',
        'Sphinx>=1.4.1,<2.0.0',
        'tox>=2.3.1,<3.0.0',
        'virtualenv>=15.0.1,<16.0.0'
    ],
    url='https://github.com/loanzen/falcon-auth',
    version='1.0.0'
)
