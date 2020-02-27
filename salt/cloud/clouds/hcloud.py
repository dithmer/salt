# -*- coding: utf-8 -*-
import functools
import logging

from hcloud import Client

import salt.config as config

log = logging.getLogger(__name__)

__virtualname__ = 'hcloud'

hcloud_client = None


def hcloud_call(func):
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


@hcloud_call
def create(vm_):
    name = vm_['name']

    log.info(f'Der Name der VM soll {name} sein.')
