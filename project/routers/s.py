def print_address_regex():
    ip_address = "20.20.4.6", "20.30.7.5", "20.20.6.7"
    for trace_number  in ip_address:
        if "20.30" in trace_number:
            print(trace_number)
bee = print_address_regex()