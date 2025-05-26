import random
import string
import segno
import io
import base64
import secrets


def generate_qr_code(data):
    qr = segno.make(data)
    buf = io.BytesIO()
    qr.save(buf, scale=10, kind="png")
    buf.seek(0)  # Reset the buffer pointer to the beginning
    val = buf.getvalue()
    img_data = base64.b64encode(val).decode('utf-8')
    return img_data


def randomString(stingLength=10):
    letters = string.ascii_lowercase
    return ''.join(secrets.choice(letters) for i in range(stingLength))


def get_demo_credential():
    return {
        "bbs_dpk": "Base64EncodedDPK",
        "exp": 1736460313,
        "iat": 1736456713,
        "iss": "did:key:zXwpRJo7SnJrb9KaY4oNdwcmvXodZnrMs829DYYZRkoYooovQhgqFmpgHAgpFfkPmL87rekZJbeHr9Z8n2M1vosmm2Mh",
        "jti": "urn:uuid:fb5f6ceb-f8ec-4125-9d37-55a6b1dd34d1",
        "nbf": 1736456713,
        "nonce": "rpdwshuxedrdypwcw3uy",
        "signed_nonce": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6InJwZHdzaHV4ZWRyZHlwd2N3M3V5In0.ml8yAcdyCv9asQX-Y_O2z4jjE050LsCzekEtp4Mv7zqh8kW4HadVMTdQZopIdMoCq3meh3aU8QsZj7AmvJmESw",
        "sub": "did:key:zXwpRPYqxMxCPUmtZ3cFa6nspUxToczrt84uGjGPR1Pvj9hR85UbhWVF265T9rCie6fk683TQbXSM8viKxEJzgiWoyHw",
        "total_messages": 17,
        "validity_identifier": r"https://127.0.0.1:8080/validate/isvalid/pw4uynm64ap9thhcsghkr3iyd5z435hml5yb1mzpn4gjydfpxf",
        "vc.@context.0": "https://www.w3.org/2018/credentials/v1",
        "vc.credentialSchema.id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
        "vc.credentialSchema.type": "FullJsonSchemaValidator2021",
        "vc.credentialSubject.firstName": "Max",
        "vc.credentialSubject.issuanceCount": "1",
        "vc.credentialSubject.image": "Base64hereOf35x45Image600DPI",
        "vc.credentialSubject.lastName": "Musterfrau",
        "vc.credentialSubject.studentId": "123456",
        "vc.credentialSubject.studentIdPrefix": "654321",
        "vc.credentialSubject.theme.bgColorCard": "C40D1E",
        "vc.credentialSubject.theme.bgColorSectionBot": "FFFFFF",
        "vc.credentialSubject.theme.bgColorSectionTop": "C40D1E",
        "vc.credentialSubject.theme.fgColorTitle": "FFFFFF",
        "vc.credentialSubject.theme.icon": "universityIconBase64",
        "vc.credentialSubject.theme.name": "Technische Universität Berlin",
        "vc.expirationDate": "2025-01-09T22:05:13.518501",
        "vc.id": "urn:uuid:fb5f6ceb-f8ec-4125-9d37-55a6b1dd34d1",
        "vc.issuanceDate": "2025-01-09T21:05:13.518494",
        "vc.issuer": "did:key:zXwpRJo7SnJrb9KaY4oNdwcmvXodZnrMs829DYYZRkoYooovQhgqFmpgHAgpFfkPmL87rekZJbeHr9Z8n2M1vosmm2Mh",
        "vc.type.0": "VerifiableCredential",
        "vc.type.1": "VerifiableAttestation",
        "vc.type.2": "StudentIDCard",
        "vc.validFrom": "2025-01-09T21:05:13.518499"
    }
