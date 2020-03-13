# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals
import functools
import logging
import time
import pprint

import hcloud
from hcloud.hcloud import APIException
from hcloud.server_types.domain import ServerType
from hcloud.servers.domain import Server
from hcloud.images.domain import Image
from hcloud.actions.domain import Action
from hcloud.locations.domain import Location
from hcloud.datacenters.domain import Datacenter

import salt.config as config
import salt.utils.files
import salt.utils.cloud
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
            hcloud_client = hcloud.Client(token=api_key)

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
def create(vm_):
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

    log.info('Sending request to create a new hetzner-cloud vm.')
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
        log.error('Could not read ssh keyfile {0}'.format(ssh_keyfile_public))
        return False

    hcloud_ssh_public_key = _hcloud_find_matching_ssh_pub_key(local_ssh_public_key)

    if hcloud_ssh_public_key is None:
        log.error('Couldn\'t find a matching ssh key in your hcloud project.')
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
            log.info('Server {0} is up running now.'.format(server.name))
            break
        else:
            log.info(
                'Waiting for server {0} to be running: {1}'.format(server.name, server.status)
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

    ret.update(_hcloud_format_server(server))

    log.info('Created Cloud VM \'{0}\''.format(name))

    __utils__['cloud.fire_event'](
        'event',
        'created instance',
        'salt/cloud/{0}/created'.format(name),
        args=__utils__['cloud.filter_event'](
            'created', vm_, ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport'])

    return ret


@refresh_hcloud_client
def avail_locations(call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function list_locations must be called with -f or --function'
        )

    try:
        formatted_locations = [_hcloud_format_location(location) for location in hcloud_client.locations.get_all()]
    except APIException as e:
        log.error(e.message)
        return

    return formatted_locations


@refresh_hcloud_client
def avail_images(call=None):
    if call == 'action':
        raise SaltCloudException(
            'The avail_images function must be called with -f or --function.'
        )

    images = hcloud_client.images.get_all()

    formatted_images = {}

    for image in images:
        if image.type == 'system':
            identifier = image.name
        else:
            # HCloud backups and snapshots are images without name, so the id is taken as identifier
            identifier = str(image.id)

        if image.status == 'available':
            formatted_images[identifier] = _hcloud_format_image(image)

    return formatted_images


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
            formatted_server_types[server_type.name] = _hcloud_format_server_type(server_type)

    return formatted_server_types


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
                                                                        for resource in
                                                                        delete_action_dict['resources']]),
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


@refresh_hcloud_client
def list_nodes(call=None):
    if call == 'action':
        raise SaltCloudException(
            'The list_nodes function must be called with -f or --function.'
        )

    try:
        servers = {server.name: _hcloud_format_server(server) for server in hcloud_client.servers.get_all()}
    except APIException as e:
        log.error(e.message)
        return False

    return servers


@refresh_hcloud_client
def list_nodes_full(call=None):
    if call == 'action':
        raise SaltCloudException(
            'The list_nodes_full function must be called with -f or --function'
        )

    try:
        servers = {server.name: _hcloud_format_server(server, full=True) for server in hcloud_client.servers.get_all()}
    except APIException as e:
        log.error(e.message)
        return False

    return servers


@refresh_hcloud_client
def list_nodes_select(call=None):
    '''
    Return a list of the VMs that are on the provider, with select fields

    Taken like this from https://docs.saltstack.com/en/latest/topics/cloud/cloud.html#the-list-nodes-select-function
    '''
    return salt.utils.cloud.list_nodes_select(
        list_nodes_full('function'), __opts__['query.selection'], call,
    )


@refresh_hcloud_client
def show_instance(name, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The show_instance action must be called with -a or --action'
        )

    try:
        server = hcloud_client.servers.get_by_name(name)
    except APIException as e:
        log.error(e.message)
        return

    return _hcloud_format_server(server, full=True)


@refresh_hcloud_client
def boot_instance(name, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The function boot_instance must be called with -a or --action'
        )

    try:
        boot_action = _hcloud_wait_for_action(
            hcloud_client.servers.power_on(
                hcloud_client.servers.get_by_name(name)
            )
        )
    except APIException as e:
        log.error(e.message)
        return

    return _hcloud_format_action(boot_action)


@refresh_hcloud_client
def shutdown_instance(name, kwargs=None, call=None):
    if kwargs is None:
        kwargs = {
            'hard': False
        }

    if call == 'function':
        raise SaltCloudException(
            'The action shutdown_instance must be called with -a or --action'
        )

    shutdown_method = hcloud_client.servers.shutdown

    # Give the opportunity to use hard power off via kwargs
    if kwargs.get('hard'):
        shutdown_method = hcloud_client.servers.power_off

    try:
        shutdown_action = _hcloud_wait_for_action(
            shutdown_method(hcloud_client.servers.get_by_name(name))
        )
    except APIException as e:
        log.error(e.message)
        return

    return _hcloud_format_action(shutdown_action)


@refresh_hcloud_client
def reboot_instance(name, kwargs=None, call=None):
    if kwargs is None:
        kwargs = {
            'hard': False
        }

    if call == 'function':
        raise SaltCloudException(
            'The action reboot_instance must be called with -a or --action'
        )

    reboot_method = hcloud_client.servers.reboot

    # Give the opportunity to use hard power off via kwargs
    if kwargs.get('hard'):
        reboot_method = hcloud_client.servers.reset

    try:
        reboot_action = _hcloud_wait_for_action(
            reboot_method(hcloud_client.servers.get_by_name(name))
        )
    except APIException as e:
        log.error(e.message)
        return

    return _hcloud_format_action(reboot_action)


@refresh_hcloud_client
def avail_datacenters(call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function list_datacenters must be called with -f or --function'
        )

    try:
        fromatted_datacenters = [_hcloud_format_datacenter(datacenter) for datacenter in
                                 hcloud_client.datacenters.get_all()]
    except APIException as e:
        log.error(e.message)
        return

    return fromatted_datacenters


def _hcloud_find_matching_ssh_pub_key(local_ssh_public_key):
    (local_algorithm, local_key, *local_host) = local_ssh_public_key.split()

    hcloud_ssh_public_keys = hcloud_client.ssh_keys.get_all()

    matching_pub_key = None
    for key in hcloud_ssh_public_keys:
        (hcloud_algorithm, hcloud_key, *hcloud_host) = key.public_key.split()
        if hcloud_algorithm == local_algorithm and hcloud_key == local_key:
            matching_pub_key = key
            break

    return matching_pub_key


def _hcloud_wait_for_action(action: Action):
    while action.status == 'running':
        action = hcloud_client.actions.get_by_id(action.id)
        log.info('Progress: {0}'.format(action.progress))
        time.sleep(1)
    return action


def _hcloud_format_location(location: Location):
    formatted_location = {
        'id': location.id,
        'name': location.name,
        'description': location.description,
        'country': location.country,
        'city': location.city,
        'latitude': location.latitude,
        'longitude': location.longitude,
        'network_zone': location.network_zone,
    }

    return formatted_location


def _hcloud_format_datacenter(datacenter: Datacenter):
    formatted_datacenter = {
        'id': datacenter.id,
        'name': datacenter.name,
        'description': datacenter.description,
        'location': datacenter.location.name,
        'server_types': {
            'available': [server_type.name for server_type in datacenter.server_types.available],
            'supported': [server_type.name for server_type in datacenter.server_types.supported],
            'available_for_migration': [server_type.name for server_type in
                                        datacenter.server_types.available_for_migration],
        },
    }

    return formatted_datacenter


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


def _hcloud_format_server(server: Server, full=False):
    server_salt = {
        'id': server.id,
        'size': server.server_type.name,
        'state': server.status,
        'private_ips': server.private_net,
        'public_ips': [server.public_net.ipv4.ip, server.public_net.ipv6.ip] + [floating_ip.ip for floating_ip in
                                                                                server.public_net.floating_ips],
    }

    if server.image is not None:
        server_salt['image'] = server.image.name
    else:
        # HCloud-API doesn't return an image if it is a backup or snapshot based server
        server_salt['image'] = 'unknown'

    if full:
        server_salt['created'] = server.created.strftime('%c')
        server_salt['datacenter'] = server.datacenter.name

        if server.iso is not None:
            # Servers iso name is only set for public iso's
            server_salt['iso'] = server.iso.name if server.iso.name is not None else server.iso.id

        server_salt['rescue_enabled'] = server.rescue_enabled
        server_salt['locked'] = server.locked

        # Backup window is only set if there are backups enabled
        if server.backup_window is not None:
            server_salt['backup_window'] = server.backup_window

        server_salt['outgoing_traffic'] = _get_formatted_bytes_string(
            server.outgoing_traffic if server.outgoing_traffic is not None else 0)
        server_salt['ingoing_traffic'] = _get_formatted_bytes_string(
            server.ingoing_traffic if server.ingoing_traffic is not None else 0)
        server_salt['included_traffic'] = _get_formatted_bytes_string(server.included_traffic)

        server_salt['protection'] = server.protection
        server_salt['labels'] = server.labels
        server_salt['volumes'] = [volume.name for volume in server.volumes]

    return server_salt


def _get_formatted_bytes_string(bytes: int):
    # yotta (10^24) should be big enough for now
    units = ['', 'k', 'M', 'G', 'T', 'P', 'Z', 'Y']

    shrinked_bytes = float(bytes)
    shrink_times = 0

    while shrinked_bytes > 1000:
        shrinked_bytes /= 1000
        shrink_times += 1

    return '{0:.3f} {1}B'.format(shrinked_bytes, units[shrink_times])


def _hcloud_format_image(image: Image):
    # TODO: Show more information as of
    #  https://hcloud-python.readthedocs.io/en/latest/api.clients.images.html#hcloud.images.domain.Image
    formatted_image = {
        'id': image.id,
        'type': image.type,
        'name': image.name,
        'description': image.description,
    }

    return formatted_image


def _hcloud_format_server_type(size: ServerType):
    formatted_server_type = {
        'id': size.id,
        'name': size.name,
        'desc': size.description,
        'cores': '{0} ({1})'.format(size.cores, size.cpu_type),
        'memory': size.memory,
        'disk': '{0} ({1})'.format(size.disk, size.storage_type)
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
