from setuptools import setup, find_packages

setup(
    name="x19",
    version="4.0.0",
    description="Autonomous AI security assessment platform",
    py_modules=["run", "cli", "x19", "agent", "tools", "constants", "config", "providers", "provider_setup", "cli_support"],
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "x19 = run:main",
        ],
    },
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.0.0",
        "PyJWT>=2.8.0",
    ],
    python_requires=">=3.9",
)
