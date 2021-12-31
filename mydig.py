import sys
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
from timeit import default_timer as timer
import datetime as dt

root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
                '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
                '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']


def do_query(domain, server, query_type, timeout=5):
    q = dns.message.make_query(domain, query_type)
    return dns.query.udp(q, server, timeout=timeout)


def dns_resolver_A_pass(result):
    # This function takes a NS, and returns its IP address. It is called when a DNS query can not be resolved in
    # one pass and the authority section has to be used to find a NS to complete the request.

    authority_NS = [result.authority[0].to_rdataset()[i].to_text()
                                      for i in range(len(result.authority[0].to_rdataset())) if result.authority[0].to_rdataset()[i].rdtype == dns.rdatatype.NS]
    success, a_rrset, rdtype = dns_resolver_type(authority_NS[0][:-1], root_servers, 'A')
    if success and rdtype == 'A':
        return a_rrset[0].to_text()
    else:
        print("Failure")
    return None


def check_answer_type(result, domain, query_type):
    # This function takes in a DNS query result, and checks if the answer section contains a record with the desired
    # type. Returns success if record with desired type is found, or if CNAME is found.

    try:
        a_rrset = result.find_rrset(result.answer, dns.name.from_text(domain), dns.rdataclass.IN, dns.rdatatype.from_text(query_type))
    except:
        # print("error,", sys.exc_info()[0])
        try:
            a_rrset = result.find_rrset(result.answer, dns.name.from_text(domain), dns.rdataclass.IN, dns.rdatatype.CNAME)
        except:
            print("Unexpected error searching answer records:", sys.exc_info()[0])
            return False, None, None
        else:
            return True, a_rrset, 'CNAME'
    else:
        return True, a_rrset, query_type


def dns_resolver_type(domain, servers, query_type):
    # A recursive DNS resolver. Takes in a list of servers to try, a domain, and a query type.

    for srv in servers:
        try:
            result = do_query(domain, srv, query_type)
        except:
            print("Unexpected error: Trying next server.", sys.exc_info()[0])
            continue
        else:
            if len(result.answer) == 0:
                # answer has not been received, check additional for NS addresses to send query
                if len(result.additional) == 0:
                    if len(result.authority) == 0:
                        print(f"Error: {domain} server IP address could not be found from this server.")
                        continue
                    else:
                        # have to do another pass to find authority NS and send request there
                        authority_NS_A = dns_resolver_A_pass(result)
                        thelist = [authority_NS_A] # have to put authority NS IP in a list to satisfy arguments
                        success, rr_set, rdtype = dns_resolver_type(domain, thelist, query_type)
                        if success:
                            return success, rr_set, rdtype
                else:
                    additional_servers = [result.additional[i].to_rdataset()[0].to_text()
                                      for i in range(len(result.additional)) if result.additional[i].to_rdataset().rdtype == dns.rdatatype.A]
                    success, a_rrset, rdtype = dns_resolver_type(domain, additional_servers, query_type)
                    if success:
                        return success, a_rrset, rdtype
                    else:
                        # try next server
                        continue
            elif len(result.answer) > 0:
                # check if NS record exists in answer section
                success, a_rrset, rdtype = check_answer_type(result, domain, query_type)
                return success, a_rrset, rdtype
    print(f"Error: {domain} server IP address could not be found from these servers.")
    print(servers)
    return False, None, None


def dns_resolver(domain, query_type, output=True):
    valid_query_types = ['A', 'NS', 'MX']
    if query_type not in valid_query_types:
        print(f"Invalid DNS query type: {query_type}")
        return
    else:
        msg = "QUESTION SECTION:\n"
        msg += str(domain)+".\t\t\tIN\t" + query_type +"\n\n"
        current_datetime = dt.datetime.now()
        start = timer()
        success, rrset, rdtype = dns_resolver_type(domain, root_servers, query_type)
        if success:
            while rdtype == 'CNAME' and success:
                success, rrset, rdtype = dns_resolver_type(rrset[0].to_text(), root_servers, query_type)
            if not success:
                print("Could not resolve.")
                return
            # End timer, because at this point we've found our results
            end = timer()
            if not output:
                return round((end-start)*1000)
            msg += "ANSWER SECTION:\n"
            for ans in rrset:
                msg += str(domain) + ".\t\tIN\t" + query_type + "\t" + str(ans.to_text()) + "\n"
            print(msg)
            print(f"Query time: {round((end-start)*1000)} msec")
            string_date = current_datetime.strftime("%c")
            print(f"WHEN: {string_date} ")
            chars_to_replace = ['\t','\n',' ']
            for char in chars_to_replace:
                msg = msg.replace(char,'')
            print(f"MSG SIZE rcvd: {len(msg)}")
            return


if __name__ == '__main__':
    name = sys.argv[1]
    dns_query_type = sys.argv[2]
    dns_resolver(name, dns_query_type)
