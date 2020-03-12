# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals
import functools
import logging
import time
import pprint

from hcloud import Client
from hcloud.hcloud import APIException
from hcloud.server_types.domain import ServerType
from hcloud.images.domain import Image

import salt.config as config
import salt.utils.files

log = logging.getLogger(__name__)

__virtualname__ = 'hcloud'

hcloud_client = None

def refresh_hcloud_client(func):
    @functools.wraps(func.__name__)
    def wrapped_hcloud_call(*args, **kwargs):
        global hcloud_client

        vm_ = get_configured_provider()
        api_key = config.get_cloud_config_value('api_key',
                                                vm_,
                                                __opts__,
                                                search_global=False)

        if hcloud_client is None:
            hcloud_client = Client(token=api_key)

        return func(*args, **kwargs)

    return wrapped_hcloud_call


def __virtual__():
    if get_configured_provider() is False:
        return False

    return __virtualname__


def get_configured_provider():
    '''
    Return the first configured instance.
    '''
    return config.is_provider_configured(
        __opts__, __active_provider_name__ or __virtualname__, ('api_key', ))


@refresh_hcloud_client
def create(vm_):
    data = {}

    name = vm_['name']
    log.info(f'Sending request to create a new hetzner-cloud vm.')

    __utils__['cloud.fire_event'](
        'event',
        'starting create',
        'salt/cloud/{0}/creating'.format(name),
        args=__utils__['cloud.filter_event'](
            'creating', vm_, ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport'])

    ssh_keyfile_public = config.get_cloud_config_value('ssh_keyfile_public',
                                                       vm_, __opts__)

    try:
        with salt.utils.files.fopen(ssh_keyfile_public) as file:
            local_ssh_public_key = file.read()
    except OSError:
        log.error(f'Could not read ssh keyfile {ssh_keyfile_public}')
        return False

    (local_algorithm, local_key, *local_host) = local_ssh_public_key.split()

    hcloud_ssh_public_keys = hcloud_client.ssh_keys.get_all()
    hcloud_ssh_public_key = None
    for key in hcloud_ssh_public_keys:
        (hcloud_algorithm, hcloud_key, *hcloud_host) = key.public_key.split()
        if hcloud_algorithm == local_algorithm and hcloud_key == local_key:
            hcloud_ssh_public_key = key
            break

    if hcloud_ssh_public_key is None:
        log.error(f'Couldn\'t find a matching ssh key in your hcloud project.')
        return False

    # TODO: server_type and image configurable
    try:
        created_server_response = hcloud_client.servers.create(
            name,
            server_type=ServerType(name="cx11"),
            image=Image(id=5924233),
            ssh_keys=[hcloud_ssh_public_key])
    except APIException as e:
        log.error(e.message)
        return False

    __utils__['cloud.fire_event'](
        'event',
        'requesting instance',
        'salt/cloud/{0}/requesting'.format(name),
        args=__utils__['cloud.filter_event'](
            'requesting', vm_, ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport'])

    while True:
        server = hcloud_client.servers.get_by_id(
            created_server_response.server.id)

        if server.status == "running":
            log.info(f'Server {server.name} is up running now.')
            break
        else:
            log.info(
                f'Waiting for server {server.name} to be running: {server.status}'
            )
            time.sleep(1)

    vm_['ssh_host'] = server.public_net.ipv4.ip
    vm_['password'] = created_server_response.root_password

    __utils__['cloud.fire_event'](
        'event',
        'waiting for ssh',
        'salt/cloud/{0}/waiting_for_ssh'.format(name),
        sock_dir=__opts__['sock_dir'],
        args={
            'ip_address': vm_['ssh_host']
        },
        transport=__opts__['transport'])

    # Bootstrap!
    ret = __utils__['cloud.bootstrap'](vm_, __opts__)

    ret.update(data)

    log.info(f'Created Cloud VM \'{name}\'')
    log.debug(f'\'{name}\' VM creation details:\n{pprint.pformat(data)}')

    __utils__['cloud.fire_event'](
        'event',
        'created instance',
        'salt/cloud/{0}/created'.format(name),
        args=__utils__['cloud.filter_event'](
            'created', vm_, ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport'])

    return ret
