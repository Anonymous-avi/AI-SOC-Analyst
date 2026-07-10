from app.services.mitre_service import get_mitre_mapping


def test_brute_force_mitre_mapping():

    mitre = get_mitre_mapping("Brute Force")

    assert mitre.tactic == "Credential Access"
    assert mitre.technique == "Brute Force"
    assert mitre.technique_id == "T1110"


def test_path_traversal_mitre_mapping():

    mitre = get_mitre_mapping("Path Traversal")

    assert mitre.tactic == "Discovery"
    assert mitre.technique == "File and Directory Discovery"
    assert mitre.technique_id == "T1083"


def test_unknown_attack_mitre_mapping():

    mitre = get_mitre_mapping("Completely Unknown Attack")

    assert mitre.tactic == "Unknown"
    assert mitre.technique == "Unknown"
    assert mitre.technique_id == "N/A"