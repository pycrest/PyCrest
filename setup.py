from setuptools import setup

setup(
    name='pycrest',
    version='0.0.6',
    packages=['pycrest'],
    url='https://github.com/pycrest/PyCrest',
    license='MIT License',
    author='Dreae',
    author_email='penitenttangentt@gmail.com',
    description='Easy interface to the CREST API',
    install_requires=['requests'],
    test_suite='nose.collector',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: Implementation :: PyPy",
    ]
)
