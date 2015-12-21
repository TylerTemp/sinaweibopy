from setuptools import setup
import sys
import os
import weibo

if sys.version_info[0] < 3:
    from codecs import open

with open(os.path.join(os.path.dirname(__file__), 'README.md'),
          'r', encoding='utf-8') as f:
    long_description = f.read()

    try:
        import pypandoc
        long_description = pypandoc.convert(
                long_description, 'rst', format='md')
    except BaseException as e:
        print(("DEBUG: README in Markdown format. It's OK if you're only "
               "installing this program. (%s)") % e)

setup(
    name='sinaweibopy',
    version=weibo.__version__,
    description='Sina Weibo OAuth 2 API Python SDK',
    long_description=long_description,
    author='Michael Liao;TylerTemp',
    author_email='tylertempdev@gmail.com',
    url='https://github.com/TylerTemp/sinaweibopy',
    download_url='https://github.com/TylerTemp/sinaweibopy/zipball/master/',
    py_modules=['weibo'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ])
