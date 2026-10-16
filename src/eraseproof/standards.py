"""Method references and prerequisites, never an assertion of conformance."""


def mapping(method):
    crypto = 'crypto' in method or 'keyslot' in method
    firmware = any(word in method for word in ('sanitize', 'secure-erase', 'format'))
    category = 'cryptographic-erase candidate' if crypto else 'firmware-erasure candidate' if firmware else 'logical-overwrite candidate'
    return {'method': method, 'method_family': category,
            'references': [{'title': 'NIST SP 800-88 Rev. 2', 'url': 'https://csrc.nist.gov/pubs/sp/800/88/r2/final'},
                           {'title': 'IEEE 2883', 'scope': 'Media-specific sanitization technique requirements; not independently assessed by this software'}],
            'conformance_assessed': False,
            'prerequisites': ['Operator-approved media and sanitization policy', 'Trust in the device vendor implementation',
                              'Media-specific technique and coverage review', 'Independent validation and retained evidence']+
                             (['Complete key-copy and encryption-lifecycle assessment'] if crypto else []),
            'statement': 'Method classification/reference only. A local software record is not NIST/IEEE certification or proof of chip-off erasure.'}
