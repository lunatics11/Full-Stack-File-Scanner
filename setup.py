from setuptools import setup, find_packages

setup(
    name="scanner_api",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'flask==2.3.2',
        'flask-wtf==1.0.0',
        'python-dotenv==1.0.0',
        'pefile==2023.2.7',
        'requests==2.31.0',
    ],
)