from setuptools import setup, find_packages

setup(
    name="incli",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "urllib3",
    ],
    entry_points={
        "console_scripts": [
            "incli=main:main",
        ],
    },
    author="dz fb",
    description="Intelligent File Upload Vulnerability Scanner",
    python_requires=">=3.7",
)
