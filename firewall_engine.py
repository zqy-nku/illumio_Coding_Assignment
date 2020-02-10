import csv
import socket, struct
import optparse
import sys

#Definiation for a Tree node
class TreeNode():
    def __init__(self):
        self.children = list()

class Firewall():

    """
    Module 1: Reads and stores the massive firewall rules.
    """

    #Read and process the input CSV file
    def __init__(self, path):
        self.trie_tree = TreeNode()
        with open(path) as f:
            reader = csv.reader(f)
            rule_line = list(reader)
            for i in range(len(rule_line)):
                self.build_trie_tree(rule_line[i], self.trie_tree, 0)

    # store the firewall rules in a trie tree
    # "line": a firewall rule
    # "node": the trie tree node
    # "level": the trie tree level, 0 - direction level, 1 - protocol level, 2 - port level, 3 - IP level
    # output: a firewall rules trie tree
    def build_trie_tree(self, line, node, level):
        if level >= len(line):
            return

        # build the direction level and protocol level
        if level <= 1:
            for i in range(len(node.children)):
                if line[level] == node.children[i][0]:
                    self.build_trie_tree(line, node.children[i][1], level+1)
                    return
            node.children.append([line[level], TreeNode()])
            self.build_trie_tree(line, node.children[-1][1], level + 1)
            return

        # build the port level
        # the ports that have same direction and same protocol stored in a sorted array.
        # each port interval contains range left bound, range right bound and the responding children node
        if level == 2:
            port_interval = self.parse_port(line[level])
            child_node = TreeNode()
            port_interval.append(child_node)
            if len(node.children) == 0:
                node.children.append(port_interval)
            else:
                index = self.binary_search(port_interval[0], node.children, 0)
                # update the port interval array
                while index >= 0:
                    # sort the array based on the left bound and right bound
                    if self.isSmaller(index, port_interval, node.children):
                        index -= 1
                    else:
                        break
                # if the port range has been exited, add responding ip address into the exiting child node list
                if self.isSame(index, port_interval, node.children):
                    child_node = node.children[index][2]
                else:
                    node.children = self.update_interval(index, port_interval, node.children)
            self.build_trie_tree(line, child_node, level+1)
            return

        # build the IP level
        # the IP address that have same direction, protocol and port range stored in a sorted array.
        if level == 3:
            ip_interval = self.parse_ip(line[level])
            if len(node.children) == 0:
                node.children.append(ip_interval)
            else:
                node.children = self.merge_interval(ip_interval, node.children)
            return


    # target: a single list contains the new interval with responding children node
    # intervals: the exiting sorted intervals array
    # idx: 0 - interval left bound, 1 - interval right bound
    def binary_search(self, target, intervals, idx):
        l, r = 0, len(intervals)-1
        while l + 1 < r:
            mid = (l + r) // 2
            if intervals[mid][idx] <= target:  #[[1,2,chid_Node]]
                l = mid
            elif intervals[mid][idx] > target:
                r = mid
        if intervals[r][idx] <= target:
            return r
        elif intervals[l][idx] <= target:
            return l
        else:
            return -1

    # convert ports into integer range form
    def parse_port(self, port):
        interval = [int(i) for i in port.split("-")]
        if len(interval) == 1:
            interval.append(interval[0])
        return interval

    # convert ip address into integer range form
    def parse_ip(self, ip):
        interval = [self.ip2int(i) for i in ip.split("-")]
        if len(interval) == 1:
            interval.append(interval[0])
        return interval

    def ip2int(self, ip):
        packedIP = socket.inet_aton(ip)
        return int(struct.unpack("!L", packedIP)[0])

    def isSmaller(self, index, target, intervals):
        if intervals[index][0] == target[0] and intervals[index][1] > target[1]:
            return True
        else:
            return False

    def isSame(self, index, target, intervals):
        if target[0] == intervals[index][0] and target[1] == intervals[index][1]:
            return True
        else:
            return False

    # update and maintain the port intervals in a sorted array
    def update_interval(self, index, target, intervals):
        intervals = intervals[:index + 1] + [target] + intervals[index + 1:]
        return intervals

    # insert the new ip address range into the sorted ip array.
    def merge_interval(self, target, intervals):
        s, e = target
        left, right = [], []
        for i in intervals:
            if i[1] < target[0]:
                left.append(i),
            elif i[0] > target[1]:
                right.append(i),
            else:
                s = min(s, target[0])
                e = max(e, target[1])
        return left + [[s, e]] + right


    """
    Module 2: Checks incoming and outgoing network traffic.
    """

    def accept_packet(self, direction, protocol, port, ip):
        # construct a input packet line
        packet = [direction, protocol, port, ip]
        return self.check_packet(packet, self.trie_tree, 0)

    def check_packet(self, packet, node, level):

        # check whether the direction and protocol match rules
        if level <= 1:
            for i in range(len(node.children)):
                if packet[level] == node.children[i][0]:
                    return self.check_packet(packet, node.children[i][1], level + 1)
            return False

        # check whether the port matches rules, apply the binary search
        if level == 2:
            index = self.binary_search(packet[level], node.children, 0)
            if index == -1:
                return False
            for i in range(index+1):
                if packet[level] <= node.children[i][1]:
                    if self.check_packet(packet, node.children[i][2], level+1):
                        return True
            return False

        #check whether the IP address matches rules, apply the binary search
        if level == 3:
            ip = self.ip2int(packet[level])
            index = self.binary_search(ip, node.children, 0)
            if node.children[index][0] <= ip <= node.children[index][1]:
                return True
            return False

#test the program
def test(input_file):
    firewall = Firewall(input_file)

    # Given test cases
    assert firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2") == True
    assert firewall.accept_packet("inbound", "udp", 53, "192.168.2.1") == True
    assert firewall.accept_packet("outbound", "tcp", 10234, "192.168.10.11") == True
    assert firewall.accept_packet("inbound", "tcp", 81, "192.168.1.2") == False
    assert firewall.accept_packet("inbound", "udp", 24, "52.12.48.92") == False
    # Additional test cases
    assert firewall.accept_packet("inbound", "tcp", 80, "192.168.2.1") == True
    assert firewall.accept_packet("inbound", "udp", 24, "52.12.48.91") == False
    assert firewall.accept_packet("inbound", "udp", 51, "192.168.2.1") == False
    assert firewall.accept_packet("inbound", "tcp", 72, "192.168.1.2") == True
    assert firewall.accept_packet("inbound", "tcp", 72, "192.168.1.3") == True
    assert firewall.accept_packet("inbound", "tcp", 80, "192.168.2.8") == True
    assert firewall.accept_packet("outbound","udp", 2000, "52.12.48.94") == False
    assert firewall.accept_packet("outbound","tcp", 1010, "52.12.48.92") == True
    assert firewall.accept_packet("inbound", "tcp", 1, "172.31.255.255") == True
    assert firewall.accept_packet("outbound","udp", 65535,"172.31.255.255") == True

    print("All test passed!")

def main():
    parser = optparse.OptionParser()
    parser.add_option('-f', '--file', help="input file(csv)")
    parser.add_option('-t', '--test', action="store_true", help="test", default=False)
    options, args = parser.parse_args()

    if not options.file:
        print("[ERROR] Please input the rules file")

    if options.test:
        test(options.file)
    else:
        try:
            firewall = Firewall(options.file)
        except:
            print("[ERROR] Can't parse input file")
            exit(-1)
        while True:
            traffic = raw_input("Enter your traffic (e.g. outbound,tcp,1010,52.12.48.92) / quit: \n")
            if traffic == 'quit':
                return
            try:
                traffic = traffic.split(',')
                direction = traffic[0].strip()
                protocol = traffic[1].strip()
                port = int(traffic[2])
                IP = traffic[3].strip()
            except:
                print("[ERROR] Wrong input format e.g. outbound,tcp,1010,52.12.48.92")
                continue
            print("Accept: " + str(firewall.accept_packet(direction, protocol, port, IP)))

if __name__== '__main__':
    main()









