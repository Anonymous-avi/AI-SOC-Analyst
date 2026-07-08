from normalizers.ssh_normalizer import normalize_ssh_event
from normalizers.apache_normalizer import normalize_apache_event


NORMALIZER_REGISTRY = {
    "ssh": normalize_ssh_event,
    "apache": normalize_apache_event
}


def get_normalizer(log_type: str):

    return NORMALIZER_REGISTRY.get(log_type)