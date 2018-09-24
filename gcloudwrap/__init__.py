#!/usr/bin/env python3
"""
wraps Google Compute Enginge (GCE) client to facilitate deployment.

For more details on Google Compute API, see
https://developers.google.com/resources/api-libraries/documentation/compute/v1/python/latest/
"""

# pylint: disable=too-many-lines

import datetime
import enum
import json
import os
import pathlib
import re
import shlex
import subprocess
import time
import urllib.parse
from typing import Optional, Any, Tuple, List, Dict, MutableMapping, Union, Callable

import collections
import googleapiclient.discovery


class OperationStatus(enum.Enum):
    """ represents the status of an Google cloud operation. """
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"


class OperationError:
    """ represents an error which occurred during a Google cloud operation. """

    def __init__(self) -> None:
        self.message = None  # type: Optional[str]
        self.code = ''
        self.location = None  # type: Optional[str]


def _parse_operation_error(adict: Dict[str, str]) -> OperationError:
    """
    parses the operation error from a dictionary returned by a Google server.

    :param adict: to be parsed
    :return: parsed operation error
    """
    operation_error = OperationError()
    operation_error.message = adict.get("message", None)
    operation_error.code = adict["code"]
    operation_error.location = adict.get("location", None)

    return operation_error


class Operation:
    """ represents an operation. """

    def __init__(self) -> None:
        self.wrapee = None  # type: Optional[Any]
        self.name = ''
        self.status = None  # type: Optional[OperationStatus]
        self.progress = 0
        self.status_message = None  # type: Optional[str]
        self.description = None  # type: Optional[str]
        self.errors = []  # type: List[OperationError]


class ZoneOperation(Operation):
    """ represents an operation within a zone. """
    pass


class RegionOperation(Operation):
    """ represents an operation within a region. """
    pass


def _parse_operation(obj: Any, operation: Operation) -> None:
    """
    parses the operation from an untyped object in-situ.

    :param obj: to be parsed
    :return:
    """
    operation.wrapee = obj
    operation.name = str(obj['name'])
    operation.status = OperationStatus[obj['status']]
    operation.progress = int(obj['progress'])
    operation.status_message = obj.get('statusMessage', None)
    operation.description = obj.get('description', None)

    if 'error' in obj:
        operation.errors = [_parse_operation_error(adict=error) for error in obj['error']['errors']]


def _parse_zone_operation(obj: Any) -> ZoneOperation:
    """
    parses the zone operation from an untyped object.

    :param obj: to be parsed
    :return: zone operation with defined types
    """
    operation = ZoneOperation()
    _parse_operation(obj=obj, operation=operation)
    return operation


def _parse_region_operation(obj: Any) -> RegionOperation:
    """
    parses the region operation from an untyped object.

    :param obj: to be parsed
    :return: region operation with defined types
    """
    operation = RegionOperation()
    _parse_operation(obj=obj, operation=operation)
    return operation


class OperationException(Exception):
    """ represents an exception raised when an operation fails. """

    def __init__(self, operation: Operation) -> None:
        self.operation = operation

        parts = ["Operation {} failed".format(operation.name)]
        for error in operation.errors:
            error_parts = [error.code]
            if error.message:
                error_parts.append(error.message)

            if error.location:
                error_parts.append(error.location)

            parts.append(": ".join(error_parts))

        msg = "\n".join(parts)
        super().__init__(msg)


class Compute:
    """ wraps the GCE compute client. """

    def __init__(self, resource: Any, project: str, region: str, zone: str) -> None:
        """
        :param resource: GCE compute client
        :param project: project associated with the client
        :param region: region associated with the client
        :param zone: zone associated with the client
        """
        self.resource = resource
        self.project = project
        self.region = region
        self.zone = zone

    def wait_for_zone_operation(self, operation: ZoneOperation) -> None:
        """
        waits for the zone operation to finish.

        :param operation: running in the background
        :return:
        """
        while True:
            operation_obj = self.resource.zoneOperations().get(
                project=self.project, zone=self.zone, operation=operation.name).execute()

            operation = _parse_zone_operation(obj=operation_obj)

            if operation.status == OperationStatus.DONE:
                if operation.errors:
                    raise OperationException(operation=operation)

                return

            time.sleep(1)

    def wait_for_region_operation(self, operation: RegionOperation) -> None:
        """
        waits for the region operation to finish.

        :param operation: running in the background
        :return:
        """
        while True:
            operation_obj = self.resource.regionOperations().get(
                project=self.project, region=self.region, operation=operation.name).execute()

            operation = _parse_region_operation(obj=operation_obj)
            if operation.status == OperationStatus.DONE:
                if operation.errors:
                    raise OperationException(operation=operation)

                return

            time.sleep(1)


class MachineType:
    """ represents a custom machine type. """

    def __init__(self, cpus: int, memory_in_mb: int) -> None:
        self.cpus = cpus
        self.memory_in_mb = memory_in_mb


def new_machine_type(cpus: int, memory_in_mb: int) -> MachineType:
    """
    creates a new machine type.

    :param cpus: number of CPUs, either 1 or multiple of 2, inclusive maximum 32
    :param memory_in_mb: memory in megabytes, multiple of 256
    :return: new machine type
    """
    if cpus != 1 and cpus % 2 != 0:
        raise ValueError("Expected 'cpus' to be either 1 or a multiple of 2, but got: {}".format(cpus))

    if cpus > 32:
        raise ValueError("Expected 'cpus' to be less-equal 32, but got: {}".format(cpus))

    if memory_in_mb % 256 != 0:
        raise ValueError("Expected 'memory_in_mb' to be a multiple of 256, got: {}".format(memory_in_mb))

    return MachineType(cpus=cpus, memory_in_mb=memory_in_mb)


def _parse_machine_type(url: str) -> Union[str, MachineType]:
    """
    parses the given URL which describes a machine type.

    :param url: to be parsed
    :return: string, if it's a pre-defined machine type, or MachineType if it's a custom machine type.
    """
    parsed_url = urllib.parse.urlparse(url)
    machine_type_str = os.path.basename(parsed_url.path)
    if machine_type_str.startswith("custom-"):
        _, cpus_str, memory_in_mb_str = machine_type_str.split("-")
        cpus = int(cpus_str)
        memory_in_mb = int(memory_in_mb_str)
        return MachineType(cpus=cpus, memory_in_mb=memory_in_mb)

    return machine_type_str


class DiskMode(enum.Enum):
    """ specifies available disk attachment modes. """
    READ_WRITE = "READ_WRITE"
    READ_ONLY = "READ_ONLY"


class SSHKey:
    """ represents an SSH key to be authorized with the instance. """

    def __init__(self, user: str, public_key: str) -> None:
        """
        :param user: corresponding to the key
        :param public_key: content of the public key (mind that 'public_key' is *not* the path)
        """
        if ":" in user:
            raise ValueError("Unexpected colon (':') in the user name of a SSH key: {}".format(user))

        self.user = user
        self.public_key = public_key


def ssh_keys_from_file(path: Union[str, pathlib.Path], default_user: str) -> List[SSHKey]:
    """
    reads the SSH public keys from a file where each key is stored on a separate line. All public keys

    :param path: to the file containing the SSH public keys
    :param user: to be associated with the public keys which don't have the user specified in the key prefix
    :return: list of wrapped SSH keys authorized to the user
    """
    keys = []  # type: List[SSHKey]

    with open(str(path), 'rt') as fid:
        public_keys = [line.strip() for line in fid.readlines() if line.strip()]

        for line_i, public_key in enumerate(public_keys):
            space_i = public_key.find(' ')
            if space_i == -1:
                raise ValueError("Missing prefix in the public key on line {} from {}.".format(line_i + 1, path))

            prefix = public_key[:space_i]
            dot_i = prefix.find(":")

            if dot_i >= 0:
                user = prefix[:dot_i]
                public_key = public_key[dot_i + 1:]
            else:
                user = default_user
                public_key = public_key

            keys.append(SSHKey(user=user, public_key=public_key))

    return keys


class Metadata:
    """ wraps operations on the instance meta-data. """

    def __init__(self, fingerprint: str, items: Optional[List[Dict[str, str]]] = None) -> None:
        self.fingerprint = fingerprint

        self.items = collections.OrderedDict()  # type: MutableMapping[str, str]
        if items is not None:
            for keyval in items:
                key = keyval["key"]
                value = keyval["value"]
                self.items[key] = value

    def set_ssh_keys(self, keys: List[SSHKey]) -> None:
        """
        sets the SSH keys in the meta-data record.

        :param keys: to be authorized
        :return:
        """
        if not keys:
            if 'ssh-keys' in self.items:
                del self.items['ssh-keys']
                return

        lines = ['{user}:{public_key}'.format(user=key.user, public_key=key.public_key.strip()) for key in keys]
        lines.append('')
        value = '\n'.join(lines)

        self.items['ssh-keys'] = value

    def ssh_keys(self) -> List[SSHKey]:
        """
        parses the SSH keys from the items.

        :return: list of authorized SSH keys
        """
        if 'ssh-keys' not in self.items:
            return []

        value = self.items['ssh-keys']
        lines = [line for line in value.splitlines() if line.strip()]

        keys = []  # type: List[SSHKey]
        for line in lines:
            user, public_key = line.split(':', maxsplit=1)
            keys.append(SSHKey(user=user, public_key=public_key))

        return keys


class Tags:
    """ represents instance tags. """

    def __init__(self, items: List[str], fingerprint: str) -> None:
        self.items = set(items)
        self.fingerprint = fingerprint


class AlreadyMountedError(Exception):
    """ signals that the persistent disk has been already mounted. """
    pass


class SSH:
    """
    wraps 'gcloud compute ssh' command-line interface to call commands on the instance.

    This wrapper provides only the most simple calling of the remote commands. For more complex operations, consider
    more sophisticated SSH modules such as paramiko, spur or spurplus.
    """

    def __init__(self, instance: str, user: str, compute: Compute) -> None:
        self.user = user
        self.instance = instance
        self.compute = compute

    def call(self, command: List[str]) -> int:
        """
        calls the command on the instance.

        :param command: to be executed
        :return: return code
        """
        parts = [shlex.quote(part) for part in command]
        command_str = ' '.join(parts)

        # yapf: disable
        cmd = [
            'gcloud', 'compute', 'ssh',
            '--project', self.compute.project,
            '--zone', self.compute.zone,
            '{}@{}'.format(self.user, self.instance),
            '--',
            command_str
        ]
        # yapf: enable

        return subprocess.call(cmd)

    def check_call(self, command: List[str]) -> None:
        """
        calls the command on the instance and raises RuntimeError if the return code is not 0.

        :param command: to be executed
        :return:
        """
        retcode = self.call(command=command)

        if retcode != 0:
            raise RuntimeError("Failed to execute the command (return code {}): {}".format(retcode, command))


class Operator:
    """
    executes deployment operations on a running instance.
    """

    def __init__(self, call_fn: Callable[[List[str]], int]) -> None:
        """

        :param call_fn:
            call function used to call the command on the instance. It takes command arguments as input,
            and gives a return code as output.
        """
        self.call_fn = call_fn

    def has_sudo_permissions(self) -> bool:
        """
        checks if the user has sudo permissions on the remote instance.

        :return: True if the user is a sudoer
        """
        retcode = self.call_fn(['bash', '-c', '''sudo -v
RC=$?
if [ $RC -ne 0 ]; then
    exit 10
fi'''])

        if retcode == 0:
            return True

        if retcode == 10:
            return False

        raise RuntimeError("Failed to check sudo permissions on the instance with return code {}.".format(retcode))

    def format_disk(self, device_name: str) -> None:
        """
        formats the disk (ext4) given its device name.

        :param device_name: device name corresponding to the disk
        :return:
        """
        if not self.has_sudo_permissions():
            raise PermissionError("The user does not have sudo permissions on the instance.")

        # yapf: disable
        cmd = [
            'sudo', 'mkfs.ext4', '-F', '-E', 'lazy_itable_init=0,lazy_journal_init=0,discard',
            '/dev/disk/by-id/google-{}'.format(device_name)
        ]
        # yapf: enable

        retcode = self.call_fn(cmd)
        if retcode != 0:
            raise RuntimeError("Failed to format the disk with the device name {} with return code {}".format(
                device_name, retcode))

    def mount_disk(self, device_name: str, path: Union[str, pathlib.Path]) -> None:
        """
        mounts the disk to the given path. Uses the parameters as suggested in
        https://cloud.google.com/compute/docs/disks/add-persistent-disk .

        If owner, group or mode are specified, the mount path is chown'ed, chgrp'ed and chmod'ed, respectively.

        :param device_name: device name corresponding to the disk
        :param path: mount path
        :param owner: owner of the mount path
        :param group:  group assigned to the mount path
        :param mode: mode assigned to the mount path

        :raises: FileExistsError if the 'path' already exists.
        :raises: AlreadyMountedError if the disk is already mounted.
        :raises OSError if one of the permission modification operations on the mount directory fails.

        :return:
        """
        pattern = r'^[a-zA-Z_\-0-9]+$'
        if not re.match(pattern, device_name):
            raise ValueError("Unexpected device_name, expected to match {}, got: {}".format(pattern, device_name))

        if not self.has_sudo_permissions():
            raise PermissionError("The user does not have sudo permissions on the instance.")

        # yapf: disable
        script = '''MOUNTDIR={path}
if [ -d "$MOUNTDIR" ]; then
    exit 10
fi

mkdir -p "$MOUNTDIR"
RC=$?
if [ $RC -ne 0 ]; then
    echo "Failed to create the mount directory: $MOUNTDIR"
    exit $RC
fi

DEVPTH=$(readlink -f /dev/disk/by-id/google-{device_name})
if cat /proc/mounts|awk '{{print $1}}'|grep -q -F "$DEVPTH"; then
    exit 11
fi

mount -o discard,defaults /dev/disk/by-id/google-{device_name} "$MOUNTDIR";
RC=$?
if [ $RC -ne 0 ]; then
    echo "Failed to mount the disk."
    rmdir "$MOUNTDIR"
    exit $RC
fi 
'''.format(path=shlex.quote(str(path)), device_name=device_name)
        # yapf: enable

        cmd = ['sudo', '/bin/bash', '-c', script]

        retcode = self.call_fn(cmd)
        if retcode == 0:
            pass

        elif retcode == 10:
            raise FileExistsError(
                "Path on which the disk with the device name {} is to be mounted already exists: {}".format(
                    device_name, path))
        elif retcode == 11:
            raise AlreadyMountedError("The disk with the device name {} has been already mounted.".format(device_name))

        else:
            raise RuntimeError("Failed to mount the disk with the device name {} to the path {}.".format(
                device_name, path))


class ServiceAccount:
    """
    represents a service account associated with an instance.

    :ivar email: email identifying the service account
    :vartype email: str

    :ivar scopes: authorization scopes
    :vartype scopes: List[str]
    """

    def __init__(self, email: str, scopes: List[str]) -> None:
        self.email = email
        self.scopes = scopes


class Instances:
    """ wraps operations on Google cloud instances. """

    def __init__(self, compute: Compute) -> None:
        """
        :param compute: wrapper around GCE compute client
        """
        self.compute = compute

    def exists(self, name: str) -> bool:
        """
        :param name: of the instance
        :return: True if it exists
        """
        result = self.compute.resource.instances().list(
            project=self.compute.project, zone=self.compute.zone, filter="name eq {}".format(name),
            fields='items/name').execute()

        if not result:
            return False

        return True

    def insert(self,
               name: str,
               machine_type: Union[str, MachineType],
               service_account: Optional[Union[str, ServiceAccount]] = None,
               image_family: str = "ubuntu-1604-lts",
               image_project: str = "ubuntu-os-cloud",
               address: Optional[str] = None,
               request_id: Optional[str] = None,
               wait: bool = True) -> Optional[ZoneOperation]:
        """
        creates a Google cloud instance.

        :param name: of the instance
        :param machine_type:
            of the instance. If it is a string, designates a pre-defined machine type. Run
            'gcloud compute machine-types list' for a list of pre-defined machine types.

            If it is a MachineType, designates a custom machine type.
        :param service_account:
            (from https://cloud.google.com/sdk/gcloud/reference/compute/instances/create)
            A service account is an identity attached to the instance. Its access tokens can be accessed through the
            instance metadata server and are used to authenticate applications on the instance. The account can be
            either an email address or an alias corresponding to a service account. You can explicitly specify the
            Compute Engine default service account using the 'default' alias.

            If not provided, the instance will get project's default service account.
        :param image_family:
            (from https://cloud.google.com/sdk/gcloud/reference/compute/instances/create)
            the family of the image that the boot disk will be initialized with.
        :param image_project:
            (from https://cloud.google.com/sdk/gcloud/reference/compute/instances/create)
            the project against which all image and image family references will be resolved.
        :param address:
            (from https://cloud.google.com/compute/docs/reference/rest/beta/instances/insert)
            An external IP address associated with this instance. Specify an unused static external IP address available
            to the project or leave this field undefined to use an IP from a shared ephemeral IP address pool.
            If you specify a static external IP address, it must live in the same region as the zone of the instance.

            Mind that the actual IP address should be given here, not the *name* of the external address.
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: zone operation, if 'wait' not set
        """
        # pylint: disable=too-many-arguments
        # pylint: disable=too-many-locals
        image_response = self.compute.resource.images().getFromFamily(
            project=image_project, family=image_family).execute()

        source_disk_image = image_response['selfLink']

        machine_type_url = None  # type: Optional[str]
        if isinstance(machine_type, str):
            machine_type_url = "zones/{}/machineTypes/{}".format(self.compute.zone, machine_type)
        elif isinstance(machine_type, MachineType):
            machine_type_url = "zones/{}/machineTypes/custom-{}-{}".format(self.compute.zone, machine_type.cpus,
                                                                           machine_type.memory_in_mb)
        else:
            raise TypeError("Unexpected type of 'machine_type': {}".format(type(machine_type)))

        config = {
            'name':
            name,
            'machineType':
            machine_type_url,
            'disks': [{
                'boot': True,
                'autoDelete': True,
                'initializeParams': {
                    'sourceImage': source_disk_image,
                }
            }],

            # Specify a network interface with NAT to access the public internet.
            'networkInterfaces': [{
                'network': 'global/networks/default',
                'accessConfigs': [{
                    'type': 'ONE_TO_ONE_NAT',
                    'name': 'External NAT'
                }]
            }],
        }

        if service_account is not None:
            if isinstance(service_account, str):
                config['serviceAccounts'] = [{'email': service_account}]
            elif isinstance(service_account, ServiceAccount):
                assert service_account.email is not None, "Expected the service account to have a non-None email."

                config['serviceAccounts'] = [{'email': service_account.email, 'scopes': service_account.scopes}]
            else:
                raise NotImplementedError("Unhandled service account {} of type {}".format(
                    service_account, type(service_account)))

        if address is not None:
            config['networkInterfaces'][0]['accessConfigs'][0]['natIP'] = address  # type: ignore

        operation_obj = self.compute.resource.instances().insert(
            project=self.compute.project, zone=self.compute.zone, body=config, requestId=request_id).execute()

        operation = _parse_zone_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_zone_operation(operation=operation)
            return None

        return operation

    def delete(self, instance: str, request_id: Optional[str] = None, wait: bool = True) -> Optional[ZoneOperation]:
        """
        deletes the instance.

        :param instance: name of the instance
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        operation_obj = self.compute.resource.instances().delete(
            project=self.compute.project, zone=self.compute.zone, instance=instance, requestId=request_id).execute()

        operation = _parse_zone_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_zone_operation(operation=operation)
            return None

        return operation

    def attach_disk(self,
                    instance: str,
                    disk: str,
                    device_name: Optional[str] = None,
                    mode: Optional[DiskMode] = None,
                    request_id: Optional[str] = None,
                    wait: bool = True) -> Optional[ZoneOperation]:
        """
        attaches the disk to the instance.

        :param instance: name of the instance to which we attach the disk
        :param disk: name of the disk
        :param device_name:
            specifies a unique device name; mapped to /dev/disk/by-id/google-* on a Linux OS
        :param mode:
            specifies the mode of the disk; default is READ_WRITE
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        # pylint: disable=too-many-arguments
        mode_str = mode.value if mode is not None else "READ_WRITE"

        req = {
            "source": "/compute/v1/projects/{}/zones/{}/disks/{}".format(self.compute.project, self.compute.zone, disk),
            "mode": mode_str
        }

        if device_name is not None:
            req["deviceName"] = device_name

        operation_obj = self.compute.resource.instances().attachDisk(
            project=self.compute.project, zone=self.compute.zone, instance=instance, body=req,
            requestId=request_id).execute()

        operation = _parse_zone_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_zone_operation(operation=operation)
            return None

        return operation

    def external_ip(self, instance: str) -> str:
        """
        :param instance: name of the instance
        :return: external IP address
        """
        result = self.compute.resource.instances().get(
            project=self.compute.project,
            zone=self.compute.zone,
            instance=instance,
            fields='networkInterfaces/accessConfigs/natIP').execute()

        return result['networkInterfaces'][0]['accessConfigs'][0]['natIP']

    def internal_ip(self, instance: str) -> str:
        """
        :param instance: name of the instance
        :return: internal IP address
        """
        result = self.compute.resource.instances().get(
            project=self.compute.project,
            zone=self.compute.zone,
            instance=instance,
            fields='networkInterfaces/networkIP').execute()

        return result['networkInterfaces'][0]['networkIP']

    def metadata(self, instance: str) -> Metadata:
        """
        retrieves meta-data of the instance.

        :param instance: whose meta-data we retrieve
        :return: parsed meta-data
        """
        resp = self.compute.resource.instances().get(
            project=self.compute.project, zone=self.compute.zone, instance=instance, fields="metadata").execute()

        metadata_dict = resp['metadata']
        items = None  # type: Optional[List[Dict[str, str]]]
        if 'items' in metadata_dict:
            items = metadata_dict['items']

        return Metadata(fingerprint=metadata_dict["fingerprint"], items=items)

    def set_metadata(self, instance: str, metadata: Metadata, request_id: Optional[str] = None,
                     wait: bool = True) -> Optional[ZoneOperation]:
        """
        sets the meta-data of the instance.

        :param instance: name of the instance
        :param metadata: modified meta-data
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        req = dict()  # type: Dict[str, Any]
        req["fingerprint"] = metadata.fingerprint

        items = []  # type: List[Dict[str, str]]
        for key, value in metadata.items.items():
            items.append({"key": key, "value": value})

        req["items"] = items

        operation_obj = self.compute.resource.instances().setMetadata(
            project=self.compute.project, zone=self.compute.zone, instance=instance, body=req,
            requestId=request_id).execute()  # type: ZoneOperation

        operation = _parse_zone_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_zone_operation(operation=operation)
            return None

        return operation

    def tags(self, instance: str) -> Tags:
        """
        retrieves the tags of the given instance.

        :param instance: name of the instance
        :return: fingerprinted tags
        """
        resp = self.compute.resource.instances().get(
            project=self.compute.project, zone=self.compute.zone, instance=instance, fields="tags").execute()

        return Tags(items=resp['tags'].get('items', []), fingerprint=resp['tags']['fingerprint'])

    def set_tags(self, instance: str, tags: Tags, request_id: Optional[str] = None,
                 wait: bool = True) -> Optional[ZoneOperation]:
        """
        sets the tags of the instance.

        :param instance: name of the instance
        :param tags: tags to set
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        req = {"fingerprint": tags.fingerprint}  # type: Dict[str, Any]

        if tags.items:
            req['items'] = sorted(tags.items)

        operation_obj = self.compute.resource.instances().setTags(
            project=self.compute.project, zone=self.compute.zone, instance=instance, body=req,
            requestId=request_id).execute()  # type: ZoneOperation

        operation = _parse_zone_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_zone_operation(operation=operation)
            return None

        return operation

    def ssh(self, instance: str, user: str, retries: int = 10, sleep: Optional[datetime.timedelta] = None) -> SSH:
        """
        tries to connect to the SSH using a wrapper around the CLI 'gcloud compute ssh'. If the connection could
        not be established, tries again after sleeping for a 'sleep' period.

        Mind that when you start an instance, SSH daemon takes some time to start up. Hence you need to keep retrying
        in the beginning till you manage to connect to a freshly started instance.

        :param instance: to connect to
        :param user: to connect as
        :param retries: how often to retry the connection
        :param sleep: how long to wait between the retries. Defaults to 2 seconds.

        :raises: subprocess.CalledProcessError if the connection could not be established.

        :return: wrapper around 'gcloud compute ssh'
        """
        caller = SSH(instance=instance, user=user, compute=self.compute)

        if sleep is None:
            sleep = datetime.timedelta(seconds=2)

        last_err = None  # type: Optional[subprocess.CalledProcessError]
        for _ in range(0, retries):
            last_err = None
            try:
                caller.call(command=["bash", "-c", "echo hello > /dev/null"])
                break
            except subprocess.CalledProcessError as err:
                last_err = err
                time.sleep(sleep.total_seconds())

        if last_err is not None:
            raise last_err  # pylint: disable=raising-bad-type

        return caller

    def machine_type(self, instance: str) -> Union[str, MachineType]:
        """
        retrieves the machine type of the instance.

        :param instance: name of the instance
        :return:
            string, if it's a pre-defined machine type, or parsed number of CPUs and memory, if it's a custom
            machine type.
        """
        resp = self.compute.resource.instances().get(
            project=self.compute.project, zone=self.compute.zone, instance=instance, fields="machineType").execute()

        return _parse_machine_type(url=resp['machineType'])


class DiskUser:
    """
    represents a user of an attached disk.
    """

    def __init__(self) -> None:
        self.project = ''
        self.zone = ''
        self.instance = ''


def _disk_user_from_url(url: str) -> DiskUser:
    """
    parses the resource URL and molds it into a DiskUser.

    :param url: resource URL
    :return: parsed disk user
    """
    parsed_url = urllib.parse.urlparse(url)
    pth = pathlib.Path(parsed_url.path)
    instance = pth.name
    zone = pth.parent.parent.name
    project = pth.parent.parent.parent.parent.name

    disk_user = DiskUser()
    disk_user.project = project
    disk_user.zone = zone
    disk_user.instance = instance
    return disk_user


class Disk:
    """ describes a disk. """

    def __init__(self) -> None:
        self.status = ''
        self.type = ''
        self.size_gb = int(0)
        self.description = None  # type: Optional[str]
        self.name = ''
        self.id = ''  # pylint: disable=invalid-name


def _disk_from_get_response(response: Any) -> Disk:
    """
    parses the disk information from the get response.

    :param response: to be parsed
    :return: parsed details about the disk
    """
    disk = Disk()
    disk.status = str(response['status'])

    parsed_type_url = urllib.parse.urlparse(response['type'])
    type_basename = os.path.basename(parsed_type_url.path)
    disk.type = type_basename

    disk.size_gb = int(response['sizeGb'])
    disk.description = response.get('description', None)
    disk.name = str(response['name'])
    disk.id = str(response['id'])

    return disk


class Disks:
    """
    wraps operations on Google cloud disks.
    """

    def __init__(self, compute: Compute) -> None:
        self.compute = compute

    def exists(self, name: str) -> bool:
        """
        :param name: of the disk
        :return: True if the disk exists
        """
        result = self.compute.resource.disks().list(
            project=self.compute.project, zone=self.compute.zone, filter="name eq {}".format(name),
            fields='items/name').execute()

        if not result:
            return False

        return True

    def users(self, disk: str) -> List[DiskUser]:
        """
        :param disk: name of the disk
        :return: list of attached users
        """
        result = self.compute.resource.disks().get(
            disk=disk, project=self.compute.project, zone=self.compute.zone, fields='users').execute()

        if 'users' not in result:
            return []

        users = result['users']
        assert isinstance(users, list)

        return [_disk_user_from_url(url=url) for url in users]

    def attached(self, disk: str) -> bool:
        """
        :param disk: name of the disk
        :return: True if the disk has been attached to one or more instances
        """
        return len(self.users(disk=disk)) > 0

    def insert(self,
               name: str,
               disk_type: Optional[str] = None,
               description: Optional[str] = None,
               size_gb: Optional[int] = None,
               labels: Dict[str, str] = None,
               request_id: Optional[int] = None,
               wait: bool = True) -> Optional[ZoneOperation]:
        """
        creates a disk.

        :param name: of the disk
        :param disk_type: type of the disk; for example, "pd-standard" or "pd-ssd"; default is pd-standard.
        :param description: of the disk
        :param size_gb: size in gigabytes; default is 500
        :param labels: to be applied to the disk
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        # pylint: disable=too-many-arguments
        if disk_type is None:
            disk_type = 'pd-standard'

        # yapf: disable
        req = {
            "name": name,
            "type": "zones/{}/diskTypes/{}".format(self.compute.zone, disk_type)
        }  # type: Dict[str, Any]
        # yapf: enable

        if description is not None:
            req['description'] = description

        if size_gb is not None:
            req['sizeGb'] = str(size_gb)
        else:
            req['sizeGb'] = '500'

        if labels is not None:
            req['labels'] = labels

        operation_obj = self.compute.resource.disks().insert(
            project=self.compute.project, zone=self.compute.zone, body=req, requestId=request_id).execute()

        operation = _parse_zone_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_zone_operation(operation=operation)
            return None

        return operation

    def delete(self, disk: str, request_id: Optional[str] = None, wait: bool = True) -> Optional[ZoneOperation]:
        """
        deletes the persistent disk.

        :param disk: name of the disk
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        operation_obj = self.compute.resource.disks().delete(
            project=self.compute.project, zone=self.compute.zone, disk=disk, requestId=request_id).execute()

        operation = _parse_zone_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_zone_operation(operation=operation)
            return None

        return operation

    def resize(self, disk: str, size_gb: int, request_id: Optional[str] = None,
               wait: bool = True) -> Optional[ZoneOperation]:
        """
        resizes the given disk.

        :param disk: name of the disk
        :param size_gb: the new size of the disk in gigabytes
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        req = {"sizeGb": str(size_gb)}

        operation_obj = self.compute.resource.disks().resize(
            project=self.compute.project, zone=self.compute.zone, disk=disk, body=req, requestId=request_id).execute()

        operation = _parse_zone_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_zone_operation(operation=operation)
            return None

        return operation

    def get(self, disk: str) -> Disk:
        """
        gets disk information.

        :param disk: name of the disk
        :return: disk details
        """
        resp = self.compute.resource.disks().get(
            project=self.compute.project, zone=self.compute.zone, disk=disk).execute()

        return _disk_from_get_response(response=resp)


class AddressType(enum.Enum):
    """ specifies available address types. """
    EXTERNAL = "EXTERNAL"
    INTERNAL = "INTERNAL"


class AddressStatus(enum.Enum):
    """ specifies possible address statuses. """
    RESERVING = "RESERVING"
    RESERVED = "RESERVED"
    IN_USE = "IN_USE"


class AddressUser:
    """
    represents a user of a reserved address.
    """

    def __init__(self) -> None:
        self.project = ''
        self.zone = ''
        self.instance = ''


def _address_user_from_url(url: str) -> AddressUser:
    """
    parses the resource URL and molds it into an AddressUser.

    :param url: resource URL
    :return: parsed address user
    """
    parsed_url = urllib.parse.urlparse(url)
    pth = pathlib.Path(parsed_url.path)
    instance = pth.name
    zone = pth.parent.parent.name
    project = pth.parent.parent.parent.parent.name

    address_user = AddressUser()
    address_user.project = project
    address_user.zone = zone
    address_user.instance = instance
    return address_user


class Address:
    """ describes the address. """

    # pylint: disable=too-many-instance-attributes

    def __init__(self) -> None:
        self.status = None  # type: Optional[AddressStatus]
        self.address_type = None  # type: Optional[AddressType]
        self.description = None  # type: Optional[str]
        self.users = []  # type: List[AddressUser]
        self.address = ''
        self.id = ''  # pylint: disable=invalid-name
        self.self_link = ''
        self.name = ''


def _address_from_get_response(response: Any) -> Address:
    """
    parses the address from a get response.

    :param response: to be parsed
    :return: parsed address details
    """
    address = Address()

    status = response["status"]

    keyerr = None  # type: Optional[KeyError]
    try:
        address.status = AddressStatus[status]
    except KeyError as err:
        keyerr = err

    if keyerr is not None:
        raise ValueError("Unexpected address status in the get address response: {}".format(status))

    address.description = response.get('description', None)

    if "users" in response:
        users = response['users']
        if not isinstance(users, list):
            raise ValueError("Unexpected type of property 'users' in the get address response: {}".format(type(users)))
        address.users = [_address_user_from_url(url=user_url) for user_url in users]

    address.address = str(response['address'])
    address.id = response["id"]
    address.self_link = response["selfLink"]
    address.name = response["name"]

    return address


class Addresses:
    """
    wraps operations on Google cloud reserved addresses.
    """

    def __init__(self, compute: Compute) -> None:
        self.compute = compute

    def exists(self, name: str) -> bool:
        """
        :param name: of the address
        :return: True if the address exists
        """
        result = self.compute.resource.addresses().list(
            project=self.compute.project,
            region=self.compute.region,
            filter="name eq {}".format(name),
            fields='items/name').execute()

        if not result:
            return False

        return True

    def insert(self,
               name: str,
               address_type: Optional[AddressType] = None,
               description: Optional[str] = None,
               request_id: Optional[str] = None,
               wait: bool = True) -> Optional[RegionOperation]:
        """
        creates a reserved address.

        :param name: of the address
        :param address_type: either INTERNAL or EXTERNAL; default is EXTERNAL
        :param description: describes the reserved address
        :param ip_version: either IPV4 or IPV6
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        # pylint: disable=too-many-arguments
        req = {"name": name}
        if address_type is not None:
            req["addressType"] = address_type.value
        else:
            req["addressType"] = "EXTERNAL"

        if description is not None:
            req["description"] = description

        operation_obj = self.compute.resource.addresses().insert(
            project=self.compute.project, region=self.compute.region, body=req, requestId=request_id).execute()

        operation = _parse_region_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_region_operation(operation=operation)
            return None

        return operation

    def get(self, address: str) -> Address:
        """
        gets the information about the address.

        :param address: to retrieve the information about
        :return: address details
        """
        resp = self.compute.resource.addresses().get(
            project=self.compute.project, region=self.compute.region, address=address).execute()

        return _address_from_get_response(response=resp)

    def status(self, address: str) -> AddressStatus:
        """
        gets the status of the address.

        :param address: to retrieve the information about
        :return: retrieved address status
        """
        resp = self.compute.resource.addresses().get(
            project=self.compute.project, region=self.compute.region, address=address, fields='status').execute()

        status = resp['status']

        keyerr = None  # type: Optional[KeyError]
        try:
            return AddressStatus[status]
        except KeyError as err:
            keyerr = err

        if keyerr is not None:
            raise ValueError("Unexpected address status in the get address response: {}".format(status))

    def is_in_use(self, address: str) -> bool:
        """
        :param address: to retrieve the information about
        :return: True if the address is in use
        """
        return self.status(address=address) == AddressStatus.IN_USE

    def static_ip(self, address: str) -> str:
        """
        gets the static IP address of the address.

        :param address: to retrieve the information about
        :return: retrieved static IP address
        """
        resp = self.compute.resource.addresses().get(
            project=self.compute.project, region=self.compute.region, address=address, fields='address').execute()
        return resp['address']

    def delete(self, address: str, request_id: Optional[str] = None, wait: bool = True) -> Optional[RegionOperation]:
        """
        deletes the address.

        :param address: to be deleted
        :param request_id:
            specifies a unique request ID; if the request times out, you can re-request with the same
            ID to make sure that the request will be processed only once.
        :param wait: if set, waits for the operation to finish
        :return: operation, if wait is False
        """
        operation_obj = self.compute.resource.addresses().delete(
            project=self.compute.project, region=self.compute.region, address=address, requestId=request_id).execute()

        operation = _parse_region_operation(obj=operation_obj)

        if wait:
            self.compute.wait_for_region_operation(operation=operation)
            return None

        return operation


def _retrieve_defaults_with_cli(project: Optional[str] = None, region: Optional[str] = None,
                                zone: Optional[str] = None) -> Tuple[str, str, str]:
    """
    retrieves defaults for the three config values. If a value is already specified, returns its supplied value.

    :param project: GCE project
    :param region: GCE region
    :param zone: GCE zone
    :return: inferred project, region, zone
    """
    if project is None or region is None or zone is None:
        # check that gcloud CLI exists, since we are dependent on it.
        #
        # (2018-05-07, Marko Ristin)
        # We could not find any documentation on how to retrieve the default config values and the closest we got
        # was: https://github.com/GoogleCloudPlatform/google-cloud-python/issues/1934
        if subprocess.call(['which', 'gcloud'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            raise RuntimeError("Could not find gcloud CLI which is used to find out the default "
                               "values of the project, region or zone. Is 'gcloud' on your path?")

        if project is None:
            cmd = ['gcloud', 'config', 'get-value', 'project', '--format', 'json']
            out = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL).strip()

            if out == '':
                raise RuntimeError("The default value of 'project' could not be retrieved with gcloud CLI. "
                                   "Did you set it with `gcloud config set`? "
                                   "The output of the command was empty: {}".format(' '.join(cmd)))

            project = json.loads(out)
            if not isinstance(project, str):
                raise TypeError("Expected 'project' returned by gcloud config CLI to be a string, got: {}".format(
                    type(project)))

        if region is None:
            cmd = ['gcloud', 'config', 'get-value', 'compute/region', '--format', 'json']
            out = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL).strip()

            if out == '':
                raise RuntimeError("The default value of 'compute/region' could not be retrieved with gcloud CLI. "
                                   "Did you set it with `gcloud config set`? "
                                   "The output of the command was empty: {}".format(' '.join(cmd)))

            region = json.loads(out)

        if zone is None:
            cmd = ['gcloud', 'config', 'get-value', 'compute/zone', '--format', 'json']
            out = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL).strip()

            if out == '':
                raise RuntimeError("The default value of 'compute/zone' could not be retrieved with gcloud CLI. "
                                   "Did you set it with `gcloud config set`? "
                                   "The output of the command was empty: {}".format(' '.join(cmd)))

            zone = json.loads(out)

    assert project is not None
    assert region is not None
    assert zone is not None

    return project, region, zone


class Gce:
    """ wraps GCE client to manage different resources in a zone/region. """

    def __init__(self, project: Optional[str] = None, region: Optional[str] = None, zone: Optional[str] = None) -> None:
        """
        :param project:
            to be used; if not specified, assumes that it can be inferred from the environment
        :param region:
            to be used; if not specified, assumes that you set the default region;
            see https://cloud.google.com/compute/docs/regions-zones/changing-default-zone-region
        :param zone:
            to be used; if not specified, assumes that you set the default zone.
        """
        project, region, zone = _retrieve_defaults_with_cli(project=project, region=region, zone=zone)

        compute_resource = googleapiclient.discovery.build('compute', 'v1')
        self.compute = Compute(resource=compute_resource, project=project, region=region, zone=zone)

        self.instances = Instances(compute=self.compute)
        self.disks = Disks(compute=self.compute)
        self.addresses = Addresses(compute=self.compute)
