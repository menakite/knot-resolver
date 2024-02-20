# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['knot_resolver_manager',
 'knot_resolver_manager.cli',
 'knot_resolver_manager.cli.cmd',
 'knot_resolver_manager.compat',
 'knot_resolver_manager.datamodel',
 'knot_resolver_manager.datamodel.templates',
 'knot_resolver_manager.datamodel.types',
 'knot_resolver_manager.kresd_controller',
 'knot_resolver_manager.kresd_controller.supervisord',
 'knot_resolver_manager.kresd_controller.supervisord.plugin',
 'knot_resolver_manager.utils',
 'knot_resolver_manager.utils.modeling']

package_data = \
{'': ['*'], 'knot_resolver_manager.datamodel.templates': ['macros/*']}

install_requires = \
['aiohttp',
 'jinja2',
 'prometheus-client',
 'pyyaml',
 'supervisor',
 'typing-extensions']

entry_points = \
{'console_scripts': ['knot-resolver = knot_resolver_manager.__main__:run',
                     'kresctl = knot_resolver_manager.cli.main:main']}

setup_kwargs = {
    'name': 'knot-resolver-manager',
    'version': '0.1.0',
    'description': 'A central management tool for multiple instances of Knot Resolver',
    'long_description': 'None',
    'author': 'Václav Šraier',
    'author_email': 'vaclav.sraier@nic.cz',
    'maintainer': 'None',
    'maintainer_email': 'None',
    'url': 'None',
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'entry_points': entry_points,
    'python_requires': '>=3.8,<4.0',
}
from build_c_extensions import *
build(setup_kwargs)

setup(**setup_kwargs)


# This setup.py was autogenerated using Poetry for backward compatibility with setuptools.
