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
from hcloud.actions.domain import Action

import salt.config as config
import salt.utils.files
from salt.exceptions import (
    SaltCloudException
)

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
        __opts__, __active_provider_name__ or __virtualname__, (
            'api_key',
            'ssh_keyfile_public',
        ))


@refresh_hcloud_client
def destroy(name, call=None):
    '''
    Destroys a HCloud-VM by name.

    name
        The name of VM to be be destroyed.

    CLI Example:

    .. code-block:: bash

        salt-cloud -d vm_name
    '''
    if call == 'function':
        raise SaltCloudException(
            'The destroy action must be called with -d, --destroy, '
            '-a or --action.'
        )

    __utils__['cloud.fire_event'](
        'event',
        'destroying instance',
        'salt/cloud/{0}/destroying'.format(name),
        args={'name': name},
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    try:
        server = hcloud_client.servers.get_by_name(name)

        delete_action = hcloud_client.servers.delete(server)
    except APIException as e:
        log.error('Could not start the deletion of server {0}: {1}'.format(name, e.message))
        return

    log.info('Action started at {0}'.format(delete_action.started.strftime('%c')))

    delete_action_dict = _hcloud_format_action(
        _hcloud_wait_for_action(delete_action)
    )

    if delete_action_dict['status'] == 'success':
        log.info('Executed {0} on {1} at {2} successfully.'.format(delete_action_dict['command'],
                                                                   ', '.join(
                                                                       ['{0} {1}'.format(resource['type'],
                                                                                         resource['id'])
                                                                        for resource in delete_action_dict['resources']]),
                                                                   delete_action_dict['finished']))
    else:
        log.error('Execution of {0} on {1} at {2} failed: {3} - {4}'.format(delete_action_dict['command'],
                                                                            ', '.join(['{0} {1}'.format(
                                                                                resource['type'], resource['id']) for
                                                                                resource in
                                                                                delete_action_dict['resources']]),
                                                                            delete_action_dict['finished'],
                                                                            delete_action_dict['error']['code'],
                                                                            delete_action_dict['error']['message']))

    __utils__['cloud.fire_event'](
        'event',
        'destroyed instance',
        'salt/cloud/{0}/destroyed'.format(name),
        args={'name': name},
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

    if __opts__.get('update_cachedir', False) is True:
        __utils__['cloud.delete_minion_cachedir'](name, __active_provider_name__.split(':')[0], __opts__)

    return delete_action_dict


def _hcloud_wait_for_action(action: Action):
    while action.status == 'running':
        action = hcloud_client.actions.get_by_id(action.id)
        log.info('Progress: {0}'.format(action.progress))
        time.sleep(1)
    return action


def _hcloud_format_action(action: Action):
    salt_dict = {
        'command': action.command,
        'resources': action.resources,
        'status': action.status,
        'started': action.started.strftime('%c'),
        'finished': action.finished.strftime('%c')
    }

    if action.status == 'error':
        salt_dict['error'] = action.error

    return salt_dict


@refresh_hcloud_client
def avail_images(call=None):
    if call == 'action':
        raise SaltCloudException(
            'The avail_images function must be called with -f or --function.'
        )

    images = hcloud_client.images.get_all()

    formatted_images = {}

    for image in images:
        if image.status == 'available':
            formatted_images[image.name] = _format_image(image)

    return formatted_images


def _format_image(image: Image):
    # TODO: Show more information as of
    #  https://hcloud-python.readthedocs.io/en/latest/api.clients.images.html#hcloud.images.domain.Image
    formatted_image = {
        'id': image.id,
        'type': image.type,
        'name': image.name,
        'description': image.description,
    }

    return formatted_image


@refresh_hcloud_client
def avail_sizes(call=None):
    if call == 'action':
        raise SaltCloudException(
            'The avail_sizes function must be called with -f or --function.'
        )

    server_types = hcloud_client.server_types.get_all()

    formatted_server_types = {}

    for server_type in server_types:
        if not server_type.deprecated:
            formatted_server_types[server_type.name] = _format_server_type(server_type)

    return formatted_server_types


def _format_server_type(size: ServerType):
    formatted_server_type = {
        'id': size.id,
        'name': size.name,
        'desc': size.description,
        'cores': f'{size.cores} ({size.cpu_type})',
        'memory': size.memory,
        'disk': f'{size.disk} ({size.storage_type})'
    }

    for price in size.prices:
        formatted_server_type[price['location']] = {
            'hourly': {
                'net': price['price_hourly']['net'],
                'gross': price['price_hourly']['gross']},
            'monthly': {
                'net': price['price_monthly']['net'],
                'gross': price['price_monthly']['gross']}
        }

    return formatted_server_type


@refresh_hcloud_client
def create(vm_):
    data = {}

    name = vm_['name']
    try:
        # Check for required profile parameters before sending any API calls.
        if vm_['profile'] and config.is_profile_configured(
            __opts__,
            __active_provider_name__ or 'hcloud',
            vm_['profile'],
            vm_=vm_) is False:
            return False
    except AttributeError:
        pass

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

    try:
        created_server_response = hcloud_client.servers.create(
            name,
            server_type=ServerType(name=vm_['size']),
            image=Image(name=vm_['image']),
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
