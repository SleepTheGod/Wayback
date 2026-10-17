from setuptools import setup

setup(
    name="waybackscanner",
    version="1.0.0",
    description="Passive Wayback archive and subdomain reconnaissance",
    py_modules=["waybackscanner"],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "waybackscanner=waybackscanner:main",
        ],
    },
)
