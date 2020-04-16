# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals
import functools
import logging
import time

import hcloud
from hcloud.hcloud import APIException
from hcloud.server_types.domain import ServerType
from hcloud.servers.domain import Server
from hcloud.images.domain import Image
from hcloud.actions.domain import Action
from hcloud.locations.domain import Location
from hcloud.datacenters.domain import Datacenter
from hcloud.ssh_keys.domain import SSHKey
from hcloud.isos.domain import Iso
from hcloud.networks.domain import Network, NetworkSubnet, NetworkRoute
from hcloud.floating_ips.domain import FloatingIP

import salt.config as config
import salt.utils.files
import salt.utils.cloud
from salt.exceptions import (
    SaltCloudException
)

log = logging.getLogger(__name__)

__virtualname__ = 'hcloud'

hcloud_client = None


def hcloud_api(func):
    '''
    Decorator for all functions which uses the hcloud-api. It refreshes the token if it was changed in the provider
    and wraps the general error handling.
    '''

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

        try:
            return func(*args, **kwargs)
        except APIException as e:
            log.error(e)
            return

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


@hcloud_api
def create(vm_):
    '''
    Create a single hcloud VM
    '''
    name = vm_['name']
    try:
        # Check for required profile parameters before sending any API calls.
        if vm_['profile'] and config.is_profile_configured(
            __opts__,
            __active_provider_name__ or 'hcloud',
            vm_['profile'],
            vm_=vm_
        ) is False:
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
        transport=__opts__['transport']
    )

    ssh_keyfile_public = config.get_cloud_config_value(
        'ssh_keyfile_public',
        vm_, __opts__
    )

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

    created_server_response = hcloud_client.servers.create(
        name,
        server_type=ServerType(name=vm_['size']),
        image=Image(name=vm_['image']),
        ssh_keys=[hcloud_ssh_public_key]
    )

    __utils__['cloud.fire_event'](
        'event',
        'requesting instance',
        'salt/cloud/{0}/requesting'.format(name),
        args=__utils__['cloud.filter_event'](
            'requesting', vm_, ['name', 'profile', 'provider', 'driver']),
        sock_dir=__opts__['sock_dir'],
        transport=__opts__['transport']
    )

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
        transport=__opts__['transport']
    )

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


@hcloud_api
def avail_locations(call=None):
    '''
    Return available hcloud locations.

    CLI-Example

    .. code-block:: bash

        salt-cloud --list-locations my-hcloud-provider
        salt-cloud -f avail_locations my-hcloud-provider
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function list_locations must be called with -f or --function'
        )

    return [_hcloud_format_location(location) for location in hcloud_client.locations.get_all()]


@hcloud_api
def avail_images(call=None):
    '''
    Return available hcloud images.

    CLI-Example

    .. code-block:: bash

        salt-cloud --list-images my-hcloud-provider
        salt-cloud -f avail_images my-hcloud-provider
    '''
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


@hcloud_api
def avail_sizes(call=None):
    '''
    Return available hcloud vm sizes

    CLI-Example

    .. code-block:: bash

        salt-cloud --list-sizes my-hcloud-provider
        salt-cloud -f avail_sizes my-hlocud-provider
    '''
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


@hcloud_api
def destroy(name, call=None):
    '''
    Destroy a hcloud vm by name.

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

    server = hcloud_client.servers.get_by_name(name)
    delete_action = hcloud_client.servers.delete(server)

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


@hcloud_api
def list_nodes(call=None):
    '''
    List hcloud vms, keeping only the most important informations.

    CLI Example:

    .. code-block:: bash

        salt-cloud -Q
        salt-cloud --query
        salt-cloud -f list_nodes my-hcloud-provider
    '''
    if call == 'action':
        raise SaltCloudException(
            'The list_nodes function must be called with -f or --function.'
        )

    return {server.name: _hcloud_format_server(server) for server in hcloud_client.servers.get_all()}


@hcloud_api
def list_nodes_full(call=None):
    '''
    List full detailed hcloud vms.

    CLI Example:

    .. code-block:: bash

        salt-cloud -F
        salt-cloud --full-query
        salt-cloud -f list_nodes_full my-hcloud-provider
    '''
    if call == 'action':
        raise SaltCloudException(
            'The list_nodes_full function must be called with -f or --function'
        )

    return {server.name: _hcloud_format_server(server, full=True) for server in hcloud_client.servers.get_all()}


@hcloud_api
def list_nodes_select(call=None):
    '''
    List the VMs that are on the provider, with select fields

    Taken like this from https://docs.saltstack.com/en/latest/topics/cloud/cloud.html#the-list-nodes-select-function
    '''
    return salt.utils.cloud.list_nodes_select(
        list_nodes_full('function'), __opts__['query.selection'], call,
    )


@hcloud_api
def show_instance(name, call=None):
    '''
    Return detailed information of a particular vm

    name
        The name of the vm to show

    CLI-Example

    .. code-block:: bash
        salt-cloud -a show_instance vm_name
    '''
    if call == 'function':
        raise SaltCloudException(
            'The show_instance action must be called with -a or --action'
        )

    server = hcloud_client.servers.get_by_name(name)

    return _hcloud_format_server(server, full=True)


@hcloud_api
def boot_instance(name, call=None):
    '''
    Start a hcloud vm

    name
        name of the vm to start

    CLI-Example

    .. code-block:: bash
        salt-cloud -a boot_instance vm_name
    '''
    if call == 'function':
        raise SaltCloudException(
            'The function boot_instance must be called with -a or --action'
        )

    boot_action = _hcloud_wait_for_action(
        hcloud_client.servers.power_on(
            hcloud_client.servers.get_by_name(name)
        )
    )

    return _hcloud_format_action(boot_action)


@hcloud_api
def shutdown_instance(name, kwargs=None, call=None):
    '''
    Hard (power off) or soft (acpi event) stop a hcloud vm

    name
        name of the vm to stop
    hard
        True or False, whether to hard stop the vm or not

    CLI-Example

    .. code-block:: bash
        salt-cloud -a shutdown_instance vm_name
        salt-cloud -a shutdown_instance vm_name hard=True
    '''
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

    shutdown_action = _hcloud_wait_for_action(
        shutdown_method(hcloud_client.servers.get_by_name(name))
    )

    return _hcloud_format_action(shutdown_action)


@hcloud_api
def reboot_instance(name, kwargs=None, call=None):
    '''
    Hard (power off) or soft (acpi event) reboot a hcloud vm

    name
        name of the vm to reboot
    hard
        True or False, whether to hard reboot the vm or not

    CLI-Example

    .. code-block:: bash
        salt-cloud -a reboot_instance vm_name
        salt-cloud -a reboot_instance vm_name hard=True
    '''
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

    reboot_action = _hcloud_wait_for_action(
        reboot_method(hcloud_client.servers.get_by_name(name))
    )

    return _hcloud_format_action(reboot_action)


@hcloud_api
def avail_datacenters(call=None):
    '''
    List all available datacenters, because hcloud utilizes locations OR datacenters

    CLI-Example

    .. code-block:: bash
        salt-cloud -f avail_datacenters my_hcloud_provider
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function list_datacenters must be called with -f or --function'
        )

    fromatted_datacenters = [_hcloud_format_datacenter(datacenter) for datacenter in
                             hcloud_client.datacenters.get_all()]

    return fromatted_datacenters


@hcloud_api
def avail_ssh_keys(call=None):
    '''
    List all available ssh keys added to the hcloud project

    CLI-Exampe

    .. code-block:: bash
        salt-cloud -f avail_ssh_keys my_hcloud_provider
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function avail_ssh_keys must be called with -f or --function'
        )

    formatted_ssh_keys = [_hcloud_format_ssh_keys(ssh_key) for ssh_key in hcloud_client.ssh_keys.get_all()]

    return formatted_ssh_keys


@hcloud_api
def avail_floating_ips(kwargs=None, call=None):
    '''
    List all available floating ips

    name
        Can be used to filter floating ips by their name
    label_selector
        Can be used to filter floating ips by labels

    CLI-Example

    .. code-block:: bash
        salt-cloud -f avail_floating_ips my_hcloud_provider name='NameFilter' label_selector='LabelFilter'
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function avail_floating_ips must be called with -f or --function'
        )

    if kwargs is None:
        kwargs = {}

    label_selector = kwargs.get('label_selector')
    name = kwargs.get('name')

    floating_ips = hcloud_client.floating_ips.get_all(label_selector=label_selector, name=name)

    return [_hcloud_format_floating_ip(floating_ip) for floating_ip in floating_ips]


def _hcloud_get_model_by_id_or_name(api, kwargs, kwarg_name):
    id_or_name = kwargs.get(kwarg_name)
    if id_or_name is None:
        raise SaltCloudException(
            'You must provide id or name as {0} in the keyword arguments'.format(kwarg_name)
        )

    try:
        model = api.get_by_id(id_or_name)
    except APIException as e:
        if e.code == 'invalid input':
            model = api.get_by_name(id_or_name)
        else:
            raise e

    return model


@hcloud_api
def floating_ip_change_dns_ptr(kwargs=None, call=None):
    '''
    Change reverse dns entry for a floating ip

    floating_ip
        (required) Id or name of the floating ip, to change the reverse dns entry of
    ip
        (required) ip address for which to set the reverse dns entry
    dns_ptr
        (optional) hostname to set as a reverse dns ptr entry, will reset to original default if not set

    CLI-Example

    .. code-block:: bash
        salt-cloud -f floating_ip_change_dns_ptr id='FloatingIpId' ip='1.1.1.1'
        salt-cloud -f floating_ip_change_dns_ptr name='FloatingIpName' ip='1.1.1.1' dns_ptr='example.com'
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function floating_ip_change_dns_ptr must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    dns_ptr = kwargs.get('dns_ptr')
    ip = kwargs.get('ip')
    if ip is None:
        raise SaltCloudException(
            'You must provide the ip for the reverse dns entry update'
        )

    floating_ip = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.floating_ips,
        kwargs=kwargs,
        kwarg_name='floating_ip'
    )

    floating_ip_change_dns_ptr_action = _hcloud_wait_for_action(
        hcloud_client.floating_ips.change_dns_ptr(
            floating_ip=floating_ip,
            ip=ip,
            dns_ptr=dns_ptr,
        )
    )

    ret.update(_hcloud_format_action(floating_ip_change_dns_ptr_action))

    return ret


@hcloud_api
def floating_ip_change_protection(kwargs=None, call=None):
    '''
    Change the protection configuration of the floating ip

    floating_ip
        (required) id or name of the floating ip
    delete
        (optional) If true, prevent the floating ip from being deleted

    CLI-Example

    .. code-block:: bash
        salt-cloud -f floating_ip_change_protection id='FloatingIpId'
        salt-cloud -f floating_ip_change_protection name='FloatingIpName' delete=True
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function floating_ip_change_protection must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    delete = kwargs.get('delete')

    floating_ip = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.floating_ips,
        kwargs=kwargs,
        kwarg_name='floating_ip'
    )

    floating_ip_change_protection_action = _hcloud_wait_for_action(
        hcloud_client.floating_ips.change_protection(floating_ip=floating_ip, delete=delete)
    )

    ret.update(_hcloud_format_action(floating_ip_change_protection_action))

    return ret


@hcloud_api
def floating_ip_create(kwargs=None, call=None):
    '''
    Creates a new floating ip.

    type
        (required) "ipv4" or "ipv6"
    server
        (optional) server to assign the floating ip to
    home_location
        (optional) home location of the floating ip. Only optional if no server is given
    description
        (optional) description for the floating ip
    name
        (optional) name of the floating ip
    labels
        (optional) user-defined labels as key-value pairs (key1:value1,key2:value2 ...)

    CLI-Example

    .. code-block:: bash
        salt-cloud -f floating_ip_create name=floating_ip_example labels=key1:value1,key2:value2 server=my_instance
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function floating_ip_create must be called with -f or --function'
        )

    if kwargs is None:
        kwargs = {}

    type = kwargs.get('type')
    if type is None:
        raise SaltCloudException(
            'You must provide the type of the floating ip to create as as keyword argument'
        )

    home_location_id_or_name = kwargs.get('home_location')
    server_id_or_name = kwargs.get('server')
    if home_location_id_or_name is None and server_id_or_name is None:
        raise SaltCloudException(
            'You must provide the id or name of a home location or server as a keyword argument'
        )

    description = kwargs.get('description')

    labels = kwargs.get('labels')
    if labels is not None:
        labels = {label.split(':')[0]: label.split(':')[1] for label in labels.split(',')}

    name = kwargs.get('name')

    ret = {}

    try:
        home_location = hcloud_client.locations.get_by_id(home_location_id_or_name)
    except APIException as e:
        if e.code == 'invalid_input':
            home_location = hcloud_client.locations.get_by_name(home_location_id_or_name)
        else:
            raise e

    try:
        server = hcloud_client.servers.get_by_id(server_id_or_name)
    except APIException as e:
        if e.code == 'invalid_input':
            server = hcloud_client.servers.get_by_name(server_id_or_name)
        else:
            raise e

    floating_ip_create_response = hcloud_client.floating_ips.create(
        home_location=home_location,
        server=server,
        type=type,
        description=description,
        labels=labels,
        name=name
    )

    floating_ip_create_action = _hcloud_wait_for_action(floating_ip_create_response.action)

    ret.update(_hcloud_format_action(floating_ip_create_action))
    ret.update({'floating_ip': _hcloud_format_floating_ip(floating_ip_create_response.floating_ip)})

    return ret


@hcloud_api
def floating_ip_delete(kwargs=None, call=None):
    '''
    Delete a floating ip

    floating_ip
        (required) name or id of the floating ip to delete

    CLI-Example

    .. code-block:: bash
            salt-cloud -f floating_ip_delete floating_ip=my_floating_ip
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function floating_ip_delete must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    floating_ip = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.floating_ips,
        kwargs=kwargs,
        kwarg_name='floating_ip'
    )

    floating_ip_deleted = hcloud_client.floating_ips.delete(floating_ip=floating_ip)

    ret.update({'deleted': floating_ip_deleted})

    return ret


@hcloud_api
def floating_ip_unassign(kwargs=None, call=None):
    '''
    Unassign a floating ip

    floating_ip
        (required) name or id of the floating ip to unassign

    CLI-Example

    .. code-block:: bash
        salt-cloud -f floating_ip_unassign floating_ip=my_floating_ip
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function floating_ip_unassing must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    floating_ip = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.floating_ips,
        kwargs=kwargs,
        kwarg_name='floating_ip'
    )

    floating_ip_unassign_action = _hcloud_wait_for_action(
        hcloud_client.floating_ips.unassign(floating_ip=floating_ip)
    )

    ret.update(_hcloud_format_action(floating_ip_unassign_action))

    return ret


@hcloud_api
def floating_ip_update(kwargs=None, call=None):
    '''
    Update a floating ip

    floating_ip
        (required) name or id of the floating ip to update
    description
        (optional) updated description of the floating ip
    labels
        (optional) updated labels as key-value pairs of the floating ip

    CLI-Example

    .. code-block:: bash
        salt-cloud -f floating_ip_update \
            floating_ip=my_floating_ip \
            description='New Description' \
            labels=key1:value1,key2:value2
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function floating_ip_update must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    description = kwargs.get('description')

    labels = kwargs.get('labels')
    if labels is not None:
        labels = {label.split(':')[0]: label.split(':')[1] for label in labels.split(',')}

    updated_name = kwargs.get('updated_name')

    floating_ip = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.floating_ips,
        kwargs=kwargs,
        kwarg_name='floating_ip'
    )

    floating_ip_updated = hcloud_client.floating_ips.update(
        floating_ip=floating_ip,
        name=updated_name,
        description=description,
        labels=labels
    )

    ret.update(_hcloud_format_floating_ip(floating_ip_updated))

    return ret


@hcloud_api
def image_change_protection(kwargs=None, call=None):
    '''
    Change protection of an image

    image
        (required) name or id of the image to change the protection of
    delete
        (optional) prevents the snapshot from being deleted if true

    CLI-Example

    .. code-block:: bash
        salt-cloud -f image_change_protection image=my_image delete=True
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function image_change_protection must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    delete = kwargs.get('delete')

    image = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.images,
        kwargs=kwargs,
        kwarg_name='image'
    )

    image_change_protection_action = _hcloud_wait_for_action(
        hcloud_client.images.change_protection(image=image, delete=delete)
    )

    ret.update(_hcloud_format_action(image_change_protection_action))

    return ret


@hcloud_api
def image_delete(kwargs=None, call=None):
    '''
    Delete an image

    image
        (required) name or id of the image to delete

    CLI-Example

    .. code-block:: bash
        salt-cloud -f image_delete image=my_image
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function image_delete must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    image = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.images,
        kwargs=kwargs,
        kwarg_name='image'
    )

    image_deleted = hcloud_client.images.delete(image=image)

    ret.update({'deleted': image_deleted})

    return ret


@hcloud_api
def image_update(kwargs=None, call=None):
    '''
    Update an image

    image
        (required) name or id of the image to update
    type
        (optional) type the image should be converted to, only `snapshot` is valid
    description
        (optional) updated description of the image
    labels
        (optional) updated labels of the image as comma seperated key-value pairs

    CLI-Example

    .. code-block:: bash
        salt-cloud -f image_update \
        image=my_image \
        type=snapshot \
        description='Updated description' \
        labels=key1:value1,key2:value2
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function image_update must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    description = kwargs.get('description')

    labels = kwargs.get('labels')
    if labels is not None:
        labels = {label.split(':')[0]: label.split(':')[1] for label in labels.split(',')}

    type = kwargs.get('type')

    image = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.images,
        kwargs=kwargs,
        kwarg_name='image'
    )

    updated_image = hcloud_client.images.update(image=image, type=type, description=description, labels=labels)

    ret.update(_hcloud_format_image(updated_image))

    return ret


@hcloud_api
def network_add_route(kwargs=None, call=None):
    '''
    Add route to network

    network
        (required) id or name of the network
    destination
        (required) destination network or host of this route
    gateway
        (required) gateway for the route

    CLI-Example

    .. code-block:: bash
        salt-cloud -f network_add_route network=my_network destination='10.100.1.0/24' gateway='10.0.1.1'
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_add_route must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    destination = kwargs.get('destination')
    if destination is None:
        raise SaltCloudException(
            'You must provide a destination as keyword argument'
        )

    gateway = kwargs.get('gateway')
    if gateway is None:
        raise SaltCloudException(
            'You must provide a gateway as keyword argument'
        )

    network_route = NetworkRoute(destination=destination, gateway=gateway)

    network = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.networks,
        kwargs=kwargs,
        kwarg_name='network'
    )

    network_add_route_action = _hcloud_wait_for_action(
        hcloud_client.networks.add_route(network=network, route=network_route)
    )

    ret.update(_hcloud_format_action(network_add_route_action))

    return ret


@hcloud_api
def network_add_subnet(kwargs=None, call=None):
    '''
    Add subnet to network
    https://docs.hetzner.cloud/#network-actions-add-a-subnet-to-a-network

    network
        (required) id or name of the network
    type
        (required) type of subnet
    ip_range
        (optional) range to allocate ips from
    network_zone
        (required) name of network zone

    CLI-Example

    .. code-block:: bash
        salt-cloud -f network_add_subnet network=my_network type=server ip_range='10.0.1.0/24' network_zone='eu-central'
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_add_subnet must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    ip_range = kwargs.get('ip_range')
    if ip_range is None:
        raise SaltCloudException(
            'You must provide ip_range as keyword argument'
        )

    type = kwargs.get('type')
    network_zone = kwargs.get('network_zone')
    gateway = kwargs.get('gateway')

    network_subnet = NetworkSubnet(ip_range=ip_range, network_zone=network_zone, gateway=gateway, type=type)

    network = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.networks,
        kwargs=kwargs,
        kwarg_name='network'
    )

    network_add_subnet_action = _hcloud_wait_for_action(
        hcloud_client.networks.add_subnet(network=network, subnet=network_subnet)
    )

    ret.update(_hcloud_format_action(network_add_subnet_action))

    return ret


@hcloud_api
def network_change_ip_range(kwargs=None, call=None):
    '''
    Change the ip range of a network
    https://docs.hetzner.cloud/#network-actions-change-ip-range-of-a-network

    network
        (required) id or name of the network
    ip_range
        (required) the new prefix for the whole network

    CLI-Example

    .. code-block::bash
        salt-cloud -f network_change_ip_range network=my_network ip_range='10.0.0.0/12'
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_change_ip_range must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    ip_range = kwargs.get('ip_range')
    if ip_range is None:
        raise SaltCloudException(
            'You must provide ip_range as keyword argument'
        )

    network = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.networks,
        kwargs=kwargs,
        kwarg_name='network'
    )

    network_change_ip_range_action = _hcloud_wait_for_action(
        hcloud_client.networks.change_ip_range(network=network, ip_range=ip_range)
    )

    ret.update(_hcloud_format_action(network_change_ip_range_action))

    return ret


@hcloud_api
def network_change_protection(kwargs=None, call=None):
    '''
    Change the protection configuration of a network
    https://docs.hetzner.cloud/#network-actions-change-network-protection

    network
        (required) id or name of the network
    delete
        (optional) if true, prevents the network from being deleted

    CLI-Example

    .. code-block:: bash
        salt-cloud -f network=my_network delete=True
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_change_protection must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    delete = kwargs.get('delete')

    network = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.networks,
        kwargs=kwargs,
        kwarg_name='network'
    )

    network_change_protection_action = _hcloud_wait_for_action(
        hcloud_client.networks.change_protection(network=network, delete=delete)
    )

    ret.update(_hcloud_format_action(network_change_protection_action))

    return ret


@hcloud_api
def network_create(kwargs=None, call=None):
    '''
    Create a network
    https://docs.hetzner.cloud/#networks-create-a-network
    To add subnets and routes like shown in the documentation, use network_add_route and network_add_subnet functions

    name
        (required) name of the network
    ip_range
        (required) ip range of the network which must span all included subnets
    labels
        (optional) networks labels as comma separated key-value pairs

    CLI-Example

    .. code-block:: bash
        salt-cloud -f network_create name=my_network ip_range='10.0.0.0/16' labels=key1:value1,key2:value2
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_create must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    name = kwargs.get('name')
    if name is None:
        raise SaltCloudException(
            'You must provide name as keyword argument'
        )

    ip_range = kwargs.get('ip_range')
    if name is None:
        raise SaltCloudException(
            'You must provide ip_range as keyword argument'
        )

    # TODO: Write subnets and routes to doc (add them by the endpoint)

    labels = kwargs.get('labels')
    if labels is not None:
        labels = {label.split(':')[0]: label.split(':')[1] for label in labels.split(',')}

    network_created = hcloud_client.networks.create(name=name, ip_range=ip_range, labels=labels)

    ret.update(_hcloud_format_network(network_created))

    return ret


@hcloud_api
def network_delete(kwargs=None, call=None):
    '''
    Delete a network
    https://docs.hetzner.cloud/#networks-delete-a-network

    network
        (required) id or name of the network

    CLI-Example

    .. code-block:: bash
        salt-cloud -f network_delete network=my_network
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_delete must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    network = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.networks,
        kwargs=kwargs,
        kwarg_name='network'
    )

    network_deleted = hcloud_client.networks.delete(network=network)

    ret.update({'deleted': network_deleted})

    return ret


@hcloud_api
def network_delete_route(kwargs=None, call=None):
    '''
    Delete a route entry from a network
    https://docs.hetzner.cloud/#network-actions-delete-a-route-from-a-network

    network
        (required) name or id of the network
    destination
        (required) destination network or host of this route
    gateway
        (required) gateway for the route

    CLI-Example

    .. code-block:: bash
        salt-cloud -f network_delete_route network=my_network destination='10.100.1.0/24' gateway='10.0.1.1'
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_delete_route must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    destination = kwargs.get('destination')
    if destination is None:
        raise SaltCloudException(
            'You must provide a destination as keyword argument'
        )

    gateway = kwargs.get('gateway')
    if gateway is None:
        raise SaltCloudException(
            'You must provide a gateway as keyword argument'
        )

    network = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.networks,
        kwargs=kwargs,
        kwarg_name='network'
    )

    network_route = NetworkRoute(destination=destination, gateway=gateway)

    network_delete_route_action = _hcloud_wait_for_action(
        hcloud_client.networks.delete_route(route=network_route)
    )

    ret.update(_hcloud_format_action(network_delete_route_action))

    return ret


@hcloud_api
def network_delete_subnet(kwargs=None, call=None):
    '''
    Delete a subnet from a network, works only if no servers are attached to the subnet
    https://docs.hetzner.cloud/#network-actions-delete-a-subnet-from-a-network

    network
        (required) id or name of the network
    ip_range
        (required) ip range of subnet to delete

    CLI-Example

    .. code-block:: bash
        salt-cloud -f network_delete_subnet network=my_network ip_range='10.0.1.0/24'
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_delete_subnet must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    ip_range = kwargs.get('ip_range')
    if ip_range is None:
        raise SaltCloudException(
            'You must provide ip_range as keyword argument'
        )

    network_subnet = NetworkSubnet(ip_range=ip_range)

    network = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.networks,
        kwargs=kwargs,
        kwarg_name='network'
    )

    network_delete_subnet_action = _hcloud_wait_for_action(
        hcloud_client.networks.delete_subnet(network=network, subnet=network_subnet)
    )

    ret.update(_hcloud_format_action(network_delete_subnet_action))

    return ret


@hcloud_api
def network_update(kwargs=None, call=None):
    '''
    Update network properties
    https://docs.hetzner.cloud/#networks-update-a-network

    network
        (required) id or name of the network
    name
        (optional) new network name
    labels
        (optional) updated labels as comma separated key-value pairs

    CLI-Example

    .. code-block:: bash
        salt-cloud -f network_update network=my_network name=my_new_network labels=key1:value1,key2:value2
    '''
    if call == 'action':
        raise SaltCloudException(
            'The function network_update must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    name = kwargs.get('name')
    labels = kwargs.get('labels')
    if labels is not None:
        labels = {label.split(':')[0]: label.split(':')[1] for label in labels.split(',')}

    network = _hcloud_get_model_by_id_or_name(
        api=hcloud_client.networks,
        kwargs=kwargs,
        kwarg_name='network',
    )

    updated_network = hcloud_client.networks.update(name=name, labels=labels)

    ret.update({'updated': _hcloud_format_network(updated_network)})

    return ret


@hcloud_api
def ssh_key_create(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function ssh_key_create must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement ssh_key_create

    return ret


@hcloud_api
def ssh_key_update(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function ssh_key_update must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement ssh_key_update

    return ret


@hcloud_api
def ssh_key_delete(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function ssh_key_delete must be called with -f or --function'
        )

    if kwargs is None:
        kwargs = {}

    ret = {}

    # TODO: Implement ssh_key_delete

    return ret


@hcloud_api
def volume_change_protection(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function volume_change_protection must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement volume_change_protection

    return ret


@hcloud_api
def volume_create(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function volume_create must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement volume_create

    return ret


@hcloud_api
def volume_delete(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function volume_delete must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement volume_delete

    return ret


@hcloud_api
def volume_detach(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function volume_detach must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement volume_detach

    return ret


@hcloud_api
def volume_resize(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function volume_resize must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement volume_resize

    return ret


@hcloud_api
def volume_update(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function volume_update must be called with -f or --function'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement volume_update

    return ret


@hcloud_api
def enable_rescue_mode(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action enable_rescue_mode must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    ssh_keys = kwargs.get('ssh_keys')
    if ssh_keys is not None:
        ssh_keys = [key for key in ssh_keys.split(',')]

    rescue_type = kwargs.get('type')

    server = hcloud_client.servers.get_by_name(name)

    enable_rescue_mode_response = hcloud_client.servers.enable_rescue(server=server, type=rescue_type,
                                                                      ssh_keys=ssh_keys)

    rescue_mode_action = _hcloud_wait_for_action(enable_rescue_mode_response.action)
    rescue_mode_root_password = enable_rescue_mode_response.root_password

    ret.update(_hcloud_format_action(rescue_mode_action))
    ret.update({'root_password': rescue_mode_root_password})

    return ret


@hcloud_api
def disable_rescue_mode(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action disable_rescue_mode must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    disable_rescue_mode_action = _hcloud_wait_for_action(
        hcloud_client.servers.disable_rescue(
            hcloud_client.servers.get_by_name(name)
        )
    )

    ret.update(_hcloud_format_action(disable_rescue_mode_action))

    return ret


@hcloud_api
def create_image(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action create_image must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    create_image_response = hcloud_client.servers.create_image(
        hcloud_client.servers.get_by_name(name),
        description=kwargs.get('description'),
        type=kwargs.get('type'),
        labels=kwargs.get('labels')
    )

    create_image_action = _hcloud_wait_for_action(create_image_response.action)
    created_image = create_image_response.image

    ret.update({'action': _hcloud_format_action(create_image_action)})
    ret.update({'image': _hcloud_format_image(created_image)})

    return ret


@hcloud_api
def change_type(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action change_type must be called with -a or --action'
        )

    ret = {}

    if kwargs is None or kwargs.get('server_type') is None or kwargs.get('upgrade_disk') is None:
        raise SaltCloudException(
            'You must provide server_type (string) and upgrade_disk (bool) in kwargs.'
        )

    change_type_action = _hcloud_wait_for_action(
        hcloud_client.servers.change_type(
            hcloud_client.servers.get_by_name(name),
            server_type=hcloud_client.server_types.get_by_name(kwargs.get('server_type')),
            upgrade_disk=kwargs.get('upgrade_disk')
        )
    )

    ret.update(_hcloud_format_action(change_type_action))

    return ret


@hcloud_api
def enable_backup(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action enable_backup must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    enable_backup_action = _hcloud_wait_for_action(
        hcloud_client.servers.enable_backup(
            hcloud_client.servers.get_by_name(name)
        )
    )

    ret.update(_hcloud_format_action(enable_backup_action))

    return ret


@hcloud_api
def disable_backup(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action disable_backup must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    disable_backup_action = _hcloud_wait_for_action(
        hcloud_client.servers.disable_backup(
            hcloud_client.servers.get_by_name(name)
        )
    )

    ret.update(_hcloud_format_action(disable_backup_action))

    return ret


@hcloud_api
def avail_isos(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function avail_isos must be called with -f or --function'
        )

    if kwargs is None:
        kwargs = {}

    name = kwargs.get('name')

    if name is not None:
        isos = hcloud_client.isos.get_all(name)
    else:
        isos = hcloud_client.isos.get_all()

    isos = [_hcloud_format_iso(iso) for iso in isos]

    return isos


@hcloud_api
def attach_iso(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action attach_iso must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    server = hcloud_client.servers.get_by_name(name)

    iso = _hcloud_get_model_by_id_or_name(api=hcloud_client.isos, kwargs=kwargs, kwarg_name='iso')

    attach_iso_action = _hcloud_wait_for_action(
        hcloud_client.servers.attach_iso(server=server, iso=iso)
    )

    ret.update(_hcloud_format_action(attach_iso_action))

    return ret


@hcloud_api
def detach_iso(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action detach_iso must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    server = hcloud_client.servers.get_by_name(name)

    detach_iso_action = _hcloud_wait_for_action(
        hcloud_client.servers.detach_iso(server=server)
    )

    ret.update(_hcloud_format_action(detach_iso_action))

    return ret


@hcloud_api
def change_dns_ptr(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action change_dns_ptr must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # No check, because None is allowed for dns_ptr
    dns_ptr = kwargs.get('dns_ptr')

    ip = kwargs.get('ip')
    if ip is None:
        raise SaltCloudException(
            'Please provide at least ip as keyword argument'
        )

    server = hcloud_client.servers.get_by_name(name)

    change_dns_ptr_action = _hcloud_wait_for_action(
        hcloud_client.servers.change_dns_ptr(server=server, ip=ip, dns_ptr=dns_ptr)
    )

    ret.update(_hcloud_format_action(change_dns_ptr_action))

    return ret


@hcloud_api
def change_protection(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action change_protection must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    delete = kwargs.get('delete')
    rebuild = kwargs.get('rebuild')

    server = hcloud_client.servers.get_by_name(name)

    change_protection_action = _hcloud_wait_for_action(
        hcloud_client.servers.change_protection(server=server, delete=delete, rebuild=rebuild)
    )

    ret.update(_hcloud_format_action(change_protection_action))

    return ret


@hcloud_api
def request_console(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action request_console must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    server = hcloud_client.servers.get_by_name(name)

    request_console_response = hcloud_client.servers.request_console(server=server)

    request_console_wss_url = request_console_response.wss_url
    request_console_password = request_console_response.password

    request_console_action = _hcloud_wait_for_action(
        request_console_response.action
    )

    ret.update({'wss_url': request_console_wss_url})
    ret.update({'password': request_console_password})

    ret.update(_hcloud_format_action(request_console_action))

    return ret


@hcloud_api
def avail_networks(kwargs=None, call=None):
    if call == 'action':
        raise SaltCloudException(
            'The function avail_networks must be called with -f or --function'
        )

    if kwargs is None:
        kwargs = {}

    name = kwargs.get('name')
    label_selector = kwargs.get('label_selector')

    networks = hcloud_client.networks.get_all(name=name, label_selector=label_selector)

    return [_hcloud_format_network(network) for network in networks]


@hcloud_api
def attach_to_network(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action attach_to_network must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    ip = kwargs.get('ip')
    alias_ips = kwargs.get('alias_ips')

    if alias_ips is not None:
        alias_ips = [ip for ip in alias_ips.split(',')]

    server = hcloud_client.servers.get_by_name(name)
    network = _hcloud_get_model_by_id_or_name(api=hcloud_client.networks, kwargs=kwargs, kwarg_name='network')

    attach_to_network_action = _hcloud_wait_for_action(
        hcloud_client.servers.attach_to_network(server=server, network=network, ip=ip, alias_ips=alias_ips)
    )

    ret.update(_hcloud_format_action(attach_to_network_action))

    return ret


@hcloud_api
def detach_from_network(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action detach_from_network must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    server = hcloud_client.servers.get_by_name(name)
    network = _hcloud_get_model_by_id_or_name(api=hcloud_client.networks, kwargs=kwargs, kwarg_name='network')

    detach_from_network_action = _hcloud_wait_for_action(
        hcloud_client.servers.detach_from_network(server=server, network=network)
    )

    ret.update(_hcloud_format_action(detach_from_network_action))

    return ret


@hcloud_api
def change_alias_ips(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action change_alias_ips must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    alias_ips = kwargs.get('alias_ips')
    if alias_ips is None:
        raise SaltCloudException(
            'Please provide alias ips of the network you want to change as a keyword argument'
        )

    alias_ips = [ip for ip in alias_ips.split(',')]

    network = _hcloud_get_model_by_id_or_name(api=hcloud_client.networks, kwargs=kwargs, kwarg_name='network')
    server = hcloud_client.servers.get_by_name(name)

    change_alias_ips_action = _hcloud_wait_for_action(
        hcloud_client.servers.change_alias_ips(server=server, network=network, alias_ips=alias_ips)
    )

    ret.update(_hcloud_format_action(change_alias_ips_action))

    return ret


@hcloud_api
def assign_floating_ip(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action assign_floating_ip must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement assign_floating_ip

    return ret


@hcloud_api
def attach_volume(name, kwargs=None, call=None):
    if call == 'function':
        raise SaltCloudException(
            'The action attach_volume must be called with -a or --action'
        )

    ret = {}

    if kwargs is None:
        kwargs = {}

    # TODO: Implement attach_volume

    return ret


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
        log.info('Progress: {0:3d}%'.format(action.progress))
        time.sleep(2)
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


def _hcloud_format_iso(iso: Iso):
    formatted_iso = {
        'id': iso.id,
        'name': iso.name,
        'description': iso.description,
        'type': iso.type,
        'deprecated': None if iso.deprecated is None else iso.deprecated.strftime('%c'),
    }

    return formatted_iso


def _hcloud_format_ssh_keys(ssh_key: SSHKey):
    formatted_ssh_key = {
        'id': ssh_key.id,
        'name': ssh_key.name,
        'fingerprint': ssh_key.fingerprint,
        'public_key': ssh_key.public_key,
        'labels': ssh_key.labels,
        'created': ssh_key.created.strftime('%c'),
    }

    return formatted_ssh_key


def _hcloud_format_network(network: Network):
    def _format_networksubnet(networksubnet: NetworkSubnet):
        formatted_networksubnet = {
            'type': networksubnet.type,
            'ip_range': networksubnet.ip_range,
            'network_zone': networksubnet.network_zone,
            'gateway': networksubnet.gateway
        }

        return formatted_networksubnet

    def _format_networkroute(networkroute: NetworkRoute):
        formatted_networkroute = {
            'destination': networkroute.destination,
            'gateway': networkroute.gateway
        }

        return formatted_networkroute

    formatted_network = {
        'id': network.id,
        'name': network.name,
        'ip_range': network.ip_range,
        'subnets': [_format_networksubnet(networksubnet) for networksubnet in network.subnets],
        'routes': [_format_networkroute(networkroute) for networkroute in network.routes],
        'servers': [_hcloud_format_server(server, full=False) for server in network.servers],
        'protection': network.protection,
        'labels': network.labels
    }

    return formatted_network


def _hcloud_format_floating_ip(floating_ip: FloatingIP):
    formatted_floating_ip = {
        'id': floating_ip.id,
        'description': floating_ip.description,
        'ip': floating_ip.ip,
        'type': floating_ip.type,
        'server': _hcloud_format_server(floating_ip.server) if floating_ip.server is not None else None,
        'dns_ptr': floating_ip.dns_ptr,
        'home_location': _hcloud_format_location(floating_ip.home_location),
        'blocked': floating_ip.blocked,
        'protection': floating_ip.protection,
        'labels': floating_ip.labels,
        'created': floating_ip.created.strftime('%c'),
        'name': floating_ip.name
    }

    return formatted_floating_ip
