from setuptools import setup, find_packages

setup(
    name='qa-tools',
    version='0.0.1',
    description='A collection of tools primarily focused on extending current OpenStack tooling.',
    author='Stephen Lowrie',
    author_email='stephen.lowrie@rackspace.com',
    url='https://github.com/arithx/qa-tools',
    packages=find_packages(exclude=('tests*', 'docs')),
    install_requires=open('requirements.txt').read(),
    license=open('LICENSE').read(),
    classifiers=(
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: Other/Proprietary License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ),
    entry_points={
        'console_scripts': [
            'subunit-verify = qa_tools.subunit_verify:entry_point',
            'subunit-describe-calls = qa_tools.describe_calls:entry_point',
            'test-loader = qa_tools.test_loader:entry_point']})
