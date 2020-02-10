# Illumio Coding Assignment

A firewall engine that can accept the incoming and outgoing network traffic based on firewall rules.

## Design and Implementation
### Module Design:
I mainly divided the firewall engine into two function modules:
1. Reads and stores the massive firewall rules.
2. Checks incoming and outgoing network traffic.

### Highlights of Implementation
I mainly applied following data structure, algorithm and methods to implement the firewall:
1. trie tree: to store the massive firewall rules in a compact form.
2. binary search:
    * to add or merge new ports intervals and new ip intervals into responding sorted arrays;
    * to quickly check whether the packet port and ip address match the rules.
3. ip2int: to convert ip address ranges into integer ranges.

## Test
I created a csv file named `rules.csv` that contains the given rules and some additional rules. Then I tested
the given test cases and certain border cases.

The results show that:
1) the programme can update and merge the port and ip address intervals correctly, the trie tree can be built efficiently, it seems that the rules stored in a compact form.
2) all test cases are passed, and the programme works well, it can accept packets very quickly.

## Performance Analysis
1. Time Complexity of building the rules Trie Tree: O(nlogn)
2. Time Complexity of accepting a packet: O(logn)

## Future optimizations
If I had more time, I would do following optimizations
1. Apply a in-memory database to store the rules trie tree. When the firewall rules increase to a very large dataset, it is more efficient for us to use a in-memory database to store the trie tree, especially when we update and access the rules dataset.
2. Improve modularity of the coding style, for example, separate the build_trie_tree() function into sub functions like build_port_level(), build_ip_level().

## How to execute:
### Run the firewall_engine.py programme
```
$ python firewall_engine.py -t -f /path/to/rules.csv
```

start firewall with rules file:
```
$ python firewall_engine.py -f /path/to/rules.csv
```

### Dependencies
1. csv
2. socket, struct
3. optparse
4. sys

## Team Preference
My preference order for the teams:
1. Data Team
2. Platform Team
3. Policy Team


Thank you for your time and consideration! I'm looking forward to hearing from you!
