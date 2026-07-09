from app.schemas.security_alert import MitreTechnique


MITRE_ATTACK_MAPPING = {

    "Brute Force": MitreTechnique(
        tactic="Credential Access",
        technique="Brute Force",
        technique_id="T1110"
    ),

    "Path Traversal": MitreTechnique(
        tactic="Discovery",
        technique="File and Directory Discovery",
        technique_id="T1083"
    )

}


def get_mitre_mapping(attack_type: str) -> MitreTechnique:

    return MITRE_ATTACK_MAPPING.get(
        attack_type,
        MitreTechnique(
            tactic="Unknown",
            technique="Unknown",
            technique_id="N/A"
        )
    )