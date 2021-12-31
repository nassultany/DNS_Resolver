from mydig import dns_resolver_A_pass
import sys
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
from timeit import default_timer as timer
import cryptography


root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
                '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
                '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

# The trust anchors in ds record text form, for easy comparison
trust_anchors_text = [
    '19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5',
    '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d'
]


def get_ksk(rrset):
    # get the ksk record from an rrset of dnskeys
    records = rrset.to_rdataset()
    for record in records:
        if record.flags == 257:
            return record


def verify_records(rrset,rrsig,keyset):
    try:
        dns.dnssec.validate(rrset, rrsig, {keyset.name:keyset})
    except dns.dnssec.ValidationFailure:
        print("Error: Could not validate records.")
        return False
    else:
        return True


def get_ds_rrset_rrsig(response):
    if len(response.authority) == 0:
        print("No DS records or signature found")
    else:
        ds_rrset,ds_rrsig = None, None
        for rrset in response.authority:
            if rrset.rdtype == 43:
                # DS records in this rrset
                ds_rrset = rrset
            elif rrset.rdtype == 46:
                # DS RRSIG
                ds_rrsig = rrset
        return ds_rrset, ds_rrsig


def get_ds_record(response):
    # check authority
    for rrset in response.authority:
        if rrset.rdtype == 43:
            return rrset[0]


def get_response(name, rdtype, server):
    qname = dns.name.from_text(name)
    dnssec_query = dns.message.make_query(qname, rdtype, want_dnssec=True)
    dnssec_respone, _ = dns.query.udp_with_fallback(dnssec_query, server)
    return dnssec_respone


def trust_root(dnskey_response):
    # verify root ksk against trust anchors

    # use dns.dnssec.make_ds to generate ds from
    dnskey_rrset, _ = dnskey_response.answer
    dnskey_ksk = get_ksk(dnskey_rrset)
    myrootksk_ds = dns.dnssec.make_ds(dns.name.root, dnskey_ksk, 'sha256')
    return myrootksk_ds.to_text() in trust_anchors_text


def get_trusted_root():
    for root_server in root_servers:
        dnskey_response = get_response(".", dns.rdatatype.DNSKEY, root_server)
        # verify its ksk against the trust anchors
        if trust_root(dnskey_response):
            # verify its zsk against its ksk
            dnskey_rrset, dnskey_rrsig = dnskey_response.answer
            if verify_records(dnskey_rrset, dnskey_rrsig, dnskey_rrset):
                # print("Verified root server.")
                return root_server, dnskey_rrset
        else:
            print(f"Could not verify root server {root_server}. Trying next one...")
    return


def get_ns_list(response):
    if len(response.authority) == 0:
        print("No NS records found")
    else:
        ns_list = []
        zone_name = None
        for rrset in response.authority:
            if rrset.rdtype == 2:
                zone_name = rrset.name.to_text()
                # NS records in this rrset
                for record in rrset:
                    ns_list.append(record.to_text())
        return ns_list, zone_name


def get_next_ns_ip(query_ns_list, query_ns_a_list):
    for ns_a_record in query_ns_a_list:
        if ns_a_record.name.to_text() in query_ns_list:
            return ns_a_record[0].to_text()
    # if additional section empty, return nothing
    return


def trust_zone(name, server, ds_rrset):
    # authenticate the zone's ksk and zsk

    response = get_response(name, dns.rdatatype.DNSKEY, server)
    dnskey_rrset, dnskey_rrsig = response.answer
    dnskey_ksk = get_ksk(dnskey_rrset)
    created_zone_ds = dns.dnssec.make_ds(name, dnskey_ksk, 'sha256')
    if ds_rrset[0] != created_zone_ds:
        return False, None
    else:
        # now verify zsk
        return verify_records(dnskey_rrset, dnskey_rrsig, dnskey_rrset), dnskey_rrset


def output(domain, answer):
    print("QUESTION SECTION:")
    print(f"{domain}.\t\t\tIN\tA\n")
    print("ANSWER SECTION:")
    for ans in answer:
        if ans.rdtype == 1:
            for rd in ans:
                print(domain + ".\t\tIN\tA\t" + rd.to_text())


def do_recursive_query(domain, server, dnskey_rrset):
    # Do actual query
    query_response = get_response(domain, dns.rdatatype.A, server)
    if len(query_response.answer) == 0:
        # NO ANSWER YET
        # check for ns for next level down and grab the zone name
        query_ns_list, zone_name = get_ns_list(query_response)

        # check for ds records in authority for next level down
        ds_rrset, ds_rrsig = get_ds_rrset_rrsig(query_response)
        if not ds_rrset or not ds_rrsig:
            print("DNSSEC not supported")
        else:
            verify_records(ds_rrset, ds_rrsig, dnskey_rrset)
            # DS verified, contact next level down (and then compare ds with their dnskey)

            next_server = get_next_ns_ip(query_ns_list, query_response.additional)
            if not next_server:
                # Have to do another pass to get ns ip as it wasn't in additional. This part does not need dnssec
                next_server = dns_resolver_A_pass(query_response)

            # now we know who we are going to talk to and their zone name. Let's verify their ksk
            # using the parent ds first and then verify their zsk and then request our desired records
            # and then verify those
            trust, newdnskey_rrset = trust_zone(zone_name, next_server, ds_rrset)
            if trust:
                #print(f"You can trust the {zone_name} zone.")
                # Now we can query it for our desired records
                do_recursive_query(domain, next_server, newdnskey_rrset)
            else:
                print(f"DNSSec verification failed.")
                return
    else:
        # Got answer. Now verify it and then output
        query_rrset, query_rrsig = query_response.answer
        verify_records(query_rrset, query_rrsig, dnskey_rrset)

        output(domain, query_response.answer)


def dnssec_recursive_resolver(domain):
    # Only have to worry about 'A' records for dnssec part as per piazza @65

    # First, have to establish a secure root server
    root_server, dnskey_rrset = get_trusted_root()
    if not root_server:
        print("No trustworthy root server found.")
        return
        # Now we have a trusted root server and can establish a chain of trust going forward

    # Do actual query
    do_recursive_query(domain, root_server, dnskey_rrset)


if __name__ == '__main__':
    # Only have to worry about 'A' records for dnssec, as per piazza @65
    name = sys.argv[1]
    dnssec_recursive_resolver(name)