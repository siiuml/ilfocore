from setuptools import setup

setup(
    name='ilfocore',
    version='0.2.12',
    description="A package provides basic, stable and"
    " authentic transmission support.",
    author='SiumLhahah',
    author_email='siumlhahah@outlook.com',
    packages=[
        'ilfocore',
        'ilfocore.lib',
        'ilfocore.utils',
    ],
    license='MIT',
    install_requires=[
         'cryptography',
    ],
)
